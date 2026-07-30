# Plan 5 — Discovery/WAYF + Logout (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** OP-Auswahl und Logout als FastAPI-Bausteine ergänzen — feste OP-EntityID (passthrough) und
eine eingebettete WAYF-Seite (OP-Auswahl, Jinja2 mit autoescape) für `/openid/login`, ein Helper zum
Auflisten föderierter OPs über den Federation-List-Endpoint, sowie best-effort RP-initiated Logout
(`/openid/logout` → `SessionBackend.revoke` + optional `end_session_endpoint`). Dabei die aus Plan 3/4
offenen Kleinigkeiten schließen (Router-Negativpfad-Tests, `/callback` OP-`error`-Param,
`CookieBackend.revoke`-Cookie-Attribute).

**Architecture:** WAYF-Renderer **gespiegelt vom SAML-Package** (Jinja2, `autoescape` zwingend an, weil
OP-Anzeigenamen/Entity-IDs aus Föderationsmetadaten stammen und untrusted sind). Discovery in `/login`:
`passthrough` nutzt `fixed_op_entity_id`; `embedded` rendert die WAYF-Seite aus `settings.op_list`; eine
explizite `?op=<entity_id>`-Auswahl gewinnt immer. Der Federation-List-Endpoint (`federation_list_endpoint`
aus der Trust-Anchor-Entity-Configuration, §8.2) wird als getesteter Fetch-Helper bereitgestellt
(Rückgabe: Liste von Entity-ID-Strings), aber v1 rendert die WAYF aus der konfigurierten `op_list` — der
Helper ist der Baustein für dynamisches Listing/Auto-Refresh (Folgeplan). Logout ist best-effort: die
lokale Session wird immer verworfen; ist `enable_op_logout` gesetzt und der OP der Session hat ein
`end_session_endpoint`, wird best-effort dorthin weitergeleitet (`client_id` + `post_logout_redirect_uri`
+ `state`), sonst lokal auf `next`.

**Tech Stack:** Python 3.12+, FastAPI, Jinja2 (WAYF), httpx (async), joserfc, Pydantic v2 +
pydantic-settings, pytest + pytest-asyncio, respx, ruff, ty, uv. Wiederverwendet Plan 2
(`federation.fetch`, `resolve_and_validate`), Plan 3 (`OidcRP`, Router, `LoginStateStore`), Plan 4
(`SessionBackend.revoke`).

## Global Constraints

- Distribution: `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header in **jeder** Quellcodedatei unter `src/`.
- Python-Floor: `>=3.12`. async-first: HTTP über `httpx.AsyncClient`.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung. Bei joserfc-Grenzen enger `cast(...)`/`# ty: ignore` (mit Begründung) erlaubt.
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren. `make lint` (scoped `src tests`) MUSS exit 0.
- **Sicherheits-Kern:** Die WAYF-Seite rendert OP-Anzeigenamen/Entity-IDs aus untrusted Föderationsmetadaten — Jinja2 MUSS mit `autoescape=select_autoescape()` konstruiert werden (XSS-Schutz). `next` und `post_logout_redirect_uri`-Rücksprünge laufen durch `is_safe_redirect`. `?op=`-Auswahl ist ein Entity-ID-String; die eigentliche Vertrauensprüfung passiert beim Login über `resolve_and_validate` (Plan 2). Kein Trust ohne validierte Trust-Chain. Keine Secrets loggen.
- **RP-Initiated Logout (Spec):** `end_session_endpoint` ist im OP nur bedingt vorhanden → fehlt es, wird lokal ausgeloggt (kein Redirect zum OP). `post_logout_redirect_uri` MUSS beim OP vorregistriert sein → die RP Entity Configuration veröffentlicht `post_logout_redirect_uris`.
- Feld-/Struktur-Ausrichtung: WAYF-Renderer spiegelt das SAML-Package (`render_wayf`, Jinja-Template, autoescape).
- Niemals `git push`. Commits auf `main` sind für dieses greenfield-Repo ausdrücklich erlaubt.
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).

### Bewusst NICHT in Plan 5 (YAGNI / Folgepläne)

- **Dynamisches WAYF-Listing im Router** (Federation-List-Endpoint live in die WAYF ziehen, Auto-Refresh, Anzeigenamen aus Resolved Metadata): der `list_subordinates`-Helper wird gebaut + getestet, aber der Router rendert v1 die statische `settings.op_list`. Dokumentierter Verzicht.
- **`id_token_hint` beim Logout:** v1 speichert das rohe id_token nicht in der Session; der end_session-Redirect nutzt `client_id` (best-effort). `id_token_hint` ist ein späterer Zusatz.
- **Front-/Back-Channel-Logout, Session Management:** später.
- **Docker/CI/Doku:** Plan 6.

## Verifizierte Fakten (Recherche — verbindlich)

- **Federation-List-Endpoint (§8.2):** `metadata.federation_entity.federation_list_endpoint` steht in der eigenen Entity Configuration des Trust Anchor/Intermediate. Request: HTTP GET, optionaler (wiederholbarer) Filter `entity_type=openid_provider`. Response: `Content-Type: application/json`, Body = **JSON-Array von Entity-ID-Strings**. Fehler: JSON `{"error": ...}` (RFC-6749-Stil), z. B. 400 `unsupported_parameter`.
- **WAYF-Anzeigename:** `metadata.openid_provider.display_name` (end-user-facing) → Fallback `organization_name` → Entity-ID. Nur nach Trust-Chain-Auflösung verfügbar; v1 nutzt die konfigurierten `op_list`-Anzeigenamen.
- **RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0):** OP-Metadatenfeld `end_session_endpoint` (nur vorhanden, wenn der OP RP-Logout unterstützt). Request-Params am end_session_endpoint: `id_token_hint` (RECOMMENDED), `client_id` (OPTIONAL, nötig ohne id_token_hint), `post_logout_redirect_uri` (OPTIONAL, MUSS vorregistriert sein), `state` (OPTIONAL, wird zurückgespiegelt). OP redirectet danach best-effort auf `post_logout_redirect_uri?state=...`. Fehlt `end_session_endpoint` → lokaler Logout.

## File Structure

```text
pyproject.toml                                        # jinja2 core dep
src/fastapi_auth/openid/settings.py                   # + discovery/logout Felder
src/fastapi_auth/openid/federation/fetch.py           # + list_subordinates()
src/fastapi_auth/openid/discovery/__init__.py
src/fastapi_auth/openid/discovery/embedded.py         # OpChoice + render_wayf (Jinja2 autoescape)
src/fastapi_auth/openid/discovery/templates/wayf.html
src/fastapi_auth/openid/router.py                     # /login discovery + /callback error + /logout
src/fastapi_auth/openid/rp.py                          # Jinja-Env (autoescape) + op_choices + logout wiring
src/fastapi_auth/openid/session/cookie.py             # revoke: Cookie-Attribute echoen
tests/oidc/conftest.py                                # OpFixture: end_session_endpoint (Erweiterung)
tests/federation/test_fetch.py                        # + list_subordinates-Tests (bestehende Datei)
tests/test_discovery.py
tests/test_router.py                                  # + Discovery/Negativpfad-Tests (bestehende Datei)
tests/test_logout.py
```

---

## Task 1: jinja2-Dependency + Discovery/Logout-Settings

**Files:**
- Modify: `pyproject.toml` (core dep `jinja2`)
- Modify: `src/fastapi_auth/openid/settings.py` (Discovery/Logout-Felder)
- Modify: `tests/test_settings.py`

**Interfaces:**
- Produces (neue Felder auf `OidcSettings`):
  - `discovery_mode: Literal["passthrough", "embedded"] = "passthrough"`, `fixed_op_entity_id: str | None = None`, `op_list: list[dict[str, str]] = []`.
  - `logout_path: str = "/openid/logout"`, `post_logout_redirect_uris: list[str] = []`, `post_logout_default: str = "/"`, `enable_op_logout: bool = False`.
  - Validierung: `logout_path` beginnt mit `mount_path`.

- [ ] **Step 1: `jinja2` in Core-Deps aufnehmen**

In `pyproject.toml` `[project].dependencies` `"jinja2>=3.1"` ergänzen. Dann:

Run: `uv pip install -U -e ".[dev]"`
Expected: `uv run python -c "import jinja2; print(jinja2.__version__)"` gibt eine 3.1+-Version.

- [ ] **Step 2: Failing test schreiben**

An `tests/test_settings.py` anhängen:

```python
def test_discovery_defaults():
    s = OidcSettings(**_BASE)
    assert s.discovery_mode == "passthrough"
    assert s.fixed_op_entity_id is None
    assert s.op_list == []


def test_logout_defaults():
    s = OidcSettings(**_BASE)
    assert s.logout_path == "/openid/logout"
    assert s.post_logout_default == "/"
    assert s.post_logout_redirect_uris == []
    assert s.enable_op_logout is False


def test_logout_path_must_be_under_mount():
    with pytest.raises(ValidationError, match="mount_path"):
        OidcSettings(**cast(dict[str, Any], {**_BASE, "logout_path": "/elsewhere/logout"}))


def test_embedded_op_list_from_values():
    s = OidcSettings(
        **cast(
            dict[str, Any],
            {
                **_BASE,
                "discovery_mode": "embedded",
                "op_list": [{"entity_id": "https://op.example", "display_name": "Example OP"}],
            },
        )
    )
    assert s.discovery_mode == "embedded"
    assert s.op_list[0]["display_name"] == "Example OP"
```

- [ ] **Step 3: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: FAIL (neue Felder/Validator fehlen).

- [ ] **Step 4: Settings erweitern**

In `src/fastapi_auth/openid/settings.py` im `OidcSettings`-Body ergänzen (nach den Security-Feldern):

```python
    # --- discovery ---
    discovery_mode: Literal["passthrough", "embedded"] = "passthrough"
    fixed_op_entity_id: str | None = None
    # Static WAYF entries for embedded discovery: [{"entity_id": ..., "display_name": ...}]
    op_list: list[dict[str, str]] = Field(default_factory=list)

    # --- logout ---
    logout_path: str = "/openid/logout"
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    post_logout_default: str = "/"
    enable_op_logout: bool = False
```

Und einen Validator (nach dem bestehenden `_check_redirect_under_mount`) ergänzen:

```python
    @model_validator(mode="after")
    def _check_logout_under_mount(self) -> OidcSettings:
        if not self.logout_path.startswith(self.mount_path):
            raise ValueError(
                f"logout_path {self.logout_path!r} must start with mount_path {self.mount_path!r}"
            )
        return self
```

- [ ] **Step 5: Test grün + ganze Suite**

Run: `uv run pytest tests/test_settings.py -q && uv run pytest -q && make lint`
Expected: alle passed; `make lint` exit 0. (Bestehende Tests konstruieren `OidcSettings` mit Default `logout_path`/`mount_path` — bleibt gültig.)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/fastapi_auth/openid/settings.py tests/test_settings.py
git commit -m "feat(discovery): Discovery-/Logout-Settings + jinja2-Dependency"
```

---

## Task 2: Federation-List-Endpoint-Fetch-Helper

**Files:**
- Modify: `src/fastapi_auth/openid/federation/fetch.py` (`list_subordinates`)
- Test: `tests/federation/test_fetch.py` (ergänzen)

**Interfaces:**
- Consumes: httpx, `errors.FetchError`.
- Produces: `async list_subordinates(client, list_endpoint, *, entity_type: str | None = None) -> list[str]` — GET auf `list_endpoint` (optional `params={"entity_type": entity_type}`), erwartet `application/json`-Array von Strings; HTTP-Fehler/Nicht-JSON-Array → `FetchError`.

- [ ] **Step 1: Failing test schreiben**

An `tests/federation/test_fetch.py` anhängen:

```python
@pytest.mark.asyncio
async def test_list_subordinates_returns_entity_ids():
    with respx.mock:
        route = respx.get("https://ta.example/list").respond(
            200,
            json=["https://op1.example", "https://op2.example"],
            headers={"content-type": "application/json"},
        )
        async with httpx.AsyncClient() as client:
            ops = await fetch.list_subordinates(
                client, "https://ta.example/list", entity_type="openid_provider"
            )
    assert ops == ["https://op1.example", "https://op2.example"]
    assert route.calls.last.request.url.params["entity_type"] == "openid_provider"


@pytest.mark.asyncio
async def test_list_subordinates_without_entity_type():
    with respx.mock:
        route = respx.get("https://ta.example/list").respond(200, json=["https://op1.example"])
        async with httpx.AsyncClient() as client:
            ops = await fetch.list_subordinates(client, "https://ta.example/list")
    assert ops == ["https://op1.example"]
    assert "entity_type" not in route.calls.last.request.url.params


@pytest.mark.asyncio
async def test_list_subordinates_http_error_raises():
    with respx.mock:
        respx.get("https://ta.example/list").respond(400, json={"error": "unsupported_parameter"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError):
                await fetch.list_subordinates(client, "https://ta.example/list")


@pytest.mark.asyncio
async def test_list_subordinates_non_array_raises():
    with respx.mock:
        respx.get("https://ta.example/list").respond(200, json={"not": "an array"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError, match="array"):
                await fetch.list_subordinates(client, "https://ta.example/list")
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_fetch.py -v -k list_subordinates`
Expected: FAIL (kein `list_subordinates`).

- [ ] **Step 3: Implementieren**

An `src/fastapi_auth/openid/federation/fetch.py` anhängen:

```python
async def list_subordinates(
    client: httpx.AsyncClient,
    list_endpoint: str,
    *,
    entity_type: str | None = None,
) -> list[str]:
    """List a superior's subordinate entity identifiers (Section 8.2).

    Optionally filtered to one ``entity_type`` (e.g. ``openid_provider``). The
    response is a JSON array of entity identifier strings.
    """
    params = {"entity_type": entity_type} if entity_type is not None else None
    try:
        response = await client.get(list_endpoint, params=params)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(f"failed to list subordinates from {list_endpoint}: {exc}") from exc
    data = response.json()
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise FetchError(f"list endpoint {list_endpoint} did not return a JSON array of strings")
    return data
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_fetch.py -v`
Expected: alle passed (bestehende + neue).

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/federation/fetch.py tests/federation/test_fetch.py
git commit -m "feat(discovery): Federation-List-Endpoint-Helper list_subordinates (Section 8.2)"
```

---

## Task 3: WAYF-Renderer

**Files:**
- Create: `src/fastapi_auth/openid/discovery/__init__.py`, `src/fastapi_auth/openid/discovery/embedded.py`, `src/fastapi_auth/openid/discovery/templates/wayf.html`
- Test: `tests/test_discovery.py`

**Interfaces:**
- Consumes: Jinja2 (`Environment`).
- Produces:
  - `@dataclass(frozen=True) OpChoice`: `entity_id: str`, `display_name: str`.
  - `TEMPLATE_NAME = "wayf.html"`.
  - `render_wayf(ops: list[OpChoice], login_path: str, next_url: str, jinja_env: Environment) -> str` — rendert eine minimale HTML-Liste; jeder Eintrag verlinkt auf `{login_path}?op=<url-encoded entity_id>&next=<url-encoded next_url>`. Anzeigenamen/Entity-IDs sind untrusted → das übergebene `jinja_env` MUSS autoescape haben (Verantwortung des Aufrufers, hier `OidcRP`).

- [ ] **Step 1: Failing test schreiben**

`tests/test_discovery.py`:

```python
"""Tests for the embedded WAYF renderer."""

from jinja2 import Environment, FileSystemLoader, select_autoescape

from fastapi_auth.openid.discovery import embedded
from fastapi_auth.openid.discovery.embedded import OpChoice


def _env() -> Environment:
    import fastapi_auth.openid.discovery as disco_pkg
    from pathlib import Path

    templates = Path(disco_pkg.__file__).parent / "templates"
    return Environment(loader=FileSystemLoader(str(templates)), autoescape=select_autoescape())


def test_render_lists_ops_with_login_links():
    ops = [
        OpChoice(entity_id="https://op1.example", display_name="OP One"),
        OpChoice(entity_id="https://op2.example", display_name="OP Two"),
    ]
    html = embedded.render_wayf(ops, "/openid/login", "/app", _env())
    assert "OP One" in html
    assert "OP Two" in html
    assert "op=https%3A%2F%2Fop1.example" in html
    assert "next=%2Fapp" in html


def test_render_escapes_untrusted_display_name():
    ops = [OpChoice(entity_id="https://evil.example", display_name="<script>alert(1)</script>")]
    html = embedded.render_wayf(ops, "/openid/login", "/app", _env())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_empty_list_produces_page():
    html = embedded.render_wayf([], "/openid/login", "/", _env())
    assert "<html" in html.lower()
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_discovery.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/discovery/__init__.py`:

```python
"""Discovery layer: embedded WAYF (OpenID Provider picker).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/openid/discovery/embedded.py`:

```python
"""Embedded Where-Are-You-From (WAYF) renderer: a self-hosted OP picker page.

Renders a minimal HTML list of OpenID Providers. Each entry links back to the
RP's own login endpoint with the chosen OP's entity id attached.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from jinja2 import Environment

TEMPLATE_NAME = "wayf.html"


@dataclass(frozen=True)
class OpChoice:
    """One selectable OpenID Provider in the WAYF picker."""

    entity_id: str
    display_name: str


def render_wayf(
    ops: list[OpChoice], login_path: str, next_url: str, jinja_env: Environment
) -> str:
    """Render the embedded WAYF page listing ``ops`` as links to ``login_path``.

    Each link is ``{login_path}?op=<url-encoded entity_id>&next=<url-encoded next_url>``.
    OP display names and entity ids originate from federation metadata and are
    therefore untrusted; the template MUST render with autoescape enabled (the
    caller is responsible for constructing ``jinja_env`` that way).
    """
    encoded_next = quote(next_url, safe="")
    entries = [
        {
            "display_name": op.display_name,
            "href": f"{login_path}?op={quote(op.entity_id, safe='')}&next={encoded_next}",
        }
        for op in ops
    ]
    template = jinja_env.get_template(TEMPLATE_NAME)
    return template.render(ops=entries)
```

`src/fastapi_auth/openid/discovery/templates/wayf.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Select your OpenID Provider</title>
  </head>
  <body>
    <h1>Select your OpenID Provider</h1>
    <ul>
      {% for op in ops %}
      <li><a href="{{ op.href }}">{{ op.display_name }}</a></li>
      {% endfor %}
    </ul>
  </body>
</html>
```

> **Umsetzungshinweis:** Die HTML-Template-Datei muss ins Package aufgenommen werden. Prüfe in `pyproject.toml`, dass `[tool.setuptools.packages.find]` das `discovery`-Subpackage einschließt (tut es via `include = ["fastapi_auth*"]`), und dass Template-Dateien mitgeliefert werden. Ergänze bei Bedarf `[tool.setuptools.package-data]` mit `"fastapi_auth.openid.discovery" = ["templates/*.html"]` und setze `include-package-data = true` (falls nicht schon). Verifiziere mit `uv run python -c "import fastapi_auth.openid.discovery as d, pathlib; print((pathlib.Path(d.__file__).parent / 'templates' / 'wayf.html').exists())"` → `True`.

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/test_discovery.py -v`
Expected: alle passed. (Der Escape-Test verifiziert, dass autoescape greift.)

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/discovery pyproject.toml tests/test_discovery.py
git commit -m "feat(discovery): eingebetteter WAYF-Renderer (Jinja2 autoescape)"
```

---

## Task 4: /login-Discovery-Routing + OidcRP-Jinja-Env

**Files:**
- Modify: `src/fastapi_auth/openid/rp.py` (autoescape-Jinja-Env + `op_choices()`)
- Modify: `src/fastapi_auth/openid/router.py` (`/login`-Discovery)
- Test: `tests/test_router.py` (Discovery-Tests ergänzen)

**Interfaces:**
- Consumes: `discovery.embedded` (`OpChoice`, `render_wayf`), Jinja2, `is_safe_redirect`.
- Produces:
  - `OidcRP`: baut ein `self.jinja_env` mit `autoescape=select_autoescape()` aus dem Package-Template-Verzeichnis; `op_choices() -> list[OpChoice]` aus `settings.op_list` (`entity_id` Pflicht, `display_name` default = `entity_id`).
  - Router `/login`: `?op=<id>` gewinnt immer → `begin_login`. Sonst: `passthrough` → `fixed_op_entity_id` (fehlt → 400); `embedded` → WAYF-Seite (`text/html`) über `render_wayf(op_choices(), mount_path + "/login", safe_next, jinja_env)`.

- [ ] **Step 1: Failing tests schreiben**

An `tests/test_router.py` anhängen (Helper `_rp` ggf. um `discovery_mode`/`op_list`/`fixed_op_entity_id` per kwargs erweitern — siehe unten):

```python
def test_login_passthrough_uses_fixed_op():
    op = OpFixture()
    rp = _rp(op, discovery_mode="passthrough", fixed_op_entity_id=OP_ENTITY)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        resp = client.get("/openid/login?next=/app", follow_redirects=False)
    assert resp.status_code == 303
    assert urlparse(resp.headers["location"]).path == "/authorize"


def test_login_passthrough_without_op_is_400():
    op = OpFixture()
    rp = _rp(op, discovery_mode="passthrough")  # no fixed_op_entity_id
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/login?next=/app", follow_redirects=False)
    assert resp.status_code == 400


def test_login_embedded_renders_wayf_page():
    op = OpFixture()
    rp = _rp(
        op,
        discovery_mode="embedded",
        op_list=[{"entity_id": OP_ENTITY, "display_name": "Example OP"}],
    )
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/login?next=/app", follow_redirects=False)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "Example OP" in resp.text
    assert "op=" in resp.text


def test_login_explicit_op_overrides_embedded():
    op = OpFixture()
    rp = _rp(op, discovery_mode="embedded", op_list=[{"entity_id": OP_ENTITY, "display_name": "X"}])
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        resp = client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
    assert resp.status_code == 303  # went straight to login, not the WAYF page
```

Passe `_rp` an, sodass es zusätzliche Settings-kwargs durchreicht:

```python
def _rp(op: OpFixture, on_auth=None, **settings_over) -> OidcRP:
    base = dict(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=_priv(op),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
    )
    base.update(settings_over)
    settings = OidcSettings(**base)  # type: ignore[arg-type]
    return OidcRP(settings, on_authenticated=on_auth, clock=lambda: NOW + 10)
```

(Bestehende `_rp(op)`- und `_rp(op, on_auth=...)`-Aufrufe bleiben kompatibel.)

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/test_router.py -v -k "login_passthrough or login_embedded or login_explicit"`
Expected: FAIL (Discovery-Routing/`op_choices`/Jinja-Env fehlen).

- [ ] **Step 3: `OidcRP` um Jinja-Env + op_choices erweitern**

In `src/fastapi_auth/openid/rp.py`: Importe ergänzen und im Konstruktor die Jinja-Env bauen.

```python
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from fastapi_auth.openid.discovery.embedded import OpChoice

_TEMPLATES_DIR = Path(__file__).parent / "discovery" / "templates"
```

Im `__init__` (nach `self.backend = ...`, vor `build_router`):

```python
        # autoescape MUST stay on: the WAYF page renders untrusted OP display
        # names / entity ids sourced from federation metadata.
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=select_autoescape()
        )
```

Methode ergänzen:

```python
    def op_choices(self) -> list[OpChoice]:
        """Build the WAYF OP list from settings.op_list (display defaults to entity_id)."""
        choices: list[OpChoice] = []
        for entry in self.settings.op_list:
            entity_id = entry.get("entity_id")
            if not entity_id:
                continue
            choices.append(OpChoice(entity_id=entity_id, display_name=entry.get("display_name") or entity_id))
        return choices
```

- [ ] **Step 4: Router `/login`-Discovery implementieren**

In `src/fastapi_auth/openid/router.py`: Importe ergänzen (`from fastapi_auth.openid.discovery.embedded import render_wayf`) und den `/login`-Handler ersetzen, sodass `op` optional ist:

```python
    @router.get("/login")
    async def login_endpoint(op: str | None = None, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, settings.allowed_redirect_hosts)
        chosen_op = op
        if chosen_op is None:
            if settings.discovery_mode == "embedded":
                html = render_wayf(
                    rp.op_choices(), f"{settings.mount_path}/login", safe_next, rp.jinja_env
                )
                return Response(html, media_type="text/html")
            # passthrough
            if settings.fixed_op_entity_id is None:
                raise HTTPException(status_code=400, detail="no OpenID Provider selected")
            chosen_op = settings.fixed_op_entity_id
        try:
            redirect = await login.begin_login(
                http_client=rp.http_client,
                settings=settings,
                fed_signing_key=rp.fed_key,
                op_entity_id=chosen_op,
                next_url=safe_next,
                state_store=rp.state_store,
                now=rp.clock(),
            )
        except OidcError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return RedirectResponse(redirect.url, status_code=303)
```

- [ ] **Step 5: Tests grün laufen lassen**

Run: `uv run pytest tests/test_router.py -v`
Expected: alle passed (bestehende + neue Discovery-Tests).

- [ ] **Step 6: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/rp.py src/fastapi_auth/openid/router.py tests/test_router.py
git commit -m "feat(discovery): /login Discovery (passthrough/embedded/?op) + WAYF-Verdrahtung"
```

---

## Task 5: /callback-OP-Fehler + Router-Negativpfad-Tests + revoke-Cookie-Attribute

**Files:**
- Modify: `src/fastapi_auth/openid/router.py` (`/callback` behandelt OP-`error`)
- Modify: `src/fastapi_auth/openid/session/cookie.py` (`revoke` echoet Cookie-Attribute)
- Test: `tests/test_router.py` (Negativpfad-Tests ergänzen)

**Interfaces:**
- Router `/callback`: akzeptiert optional `error`/`error_description`; ist `error` gesetzt → HTTP 400 mit dem OP-Fehler (vor jeder State-/Code-Verarbeitung). Bestehendes Verhalten (unbekannter/abgelaufener state → 400; fehlender code → 400; `OidcError` → 401) bleibt und wird jetzt getestet.
- `CookieBackend.revoke`: `delete_cookie` mit `path`/`samesite`/`secure` passend zum gesetzten Cookie (Browser-Kompatibilität beim Löschen).

- [ ] **Step 1: Failing tests schreiben**

An `tests/test_router.py` anhängen:

```python
def test_callback_surfaces_op_error():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get(
        "/openid/callback?state=whatever&error=access_denied&error_description=nope",
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "access_denied" in resp.text


def test_callback_unknown_state_is_400():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/callback?state=unknown&code=c", follow_redirects=False)
    assert resp.status_code == 400


def test_callback_missing_code_is_400():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
        resp = client.get(f"/openid/callback?state={state_value}", follow_redirects=False)
    assert resp.status_code == 400


def test_callback_token_failure_is_401():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
        router.post(f"{OP_ENTITY}/token").respond(400, json={"error": "invalid_grant"})
        resp = client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
    assert resp.status_code == 401
```

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/test_router.py -v -k callback`
Expected: der OP-Fehler-Test schlägt fehl (aktuell wird `error` ignoriert → generischer 400/„missing code"); die anderen bestätigen bestehendes Verhalten (können bereits grün sein).

- [ ] **Step 3: `/callback` OP-Fehler behandeln**

In `src/fastapi_auth/openid/router.py` den `/callback`-Handler um die Fehlerbehandlung erweitern (ganz am Anfang, vor dem State-Pop):

```python
    @router.get("/callback")
    async def callback(
        request: Request,
        state: str,
        code: str = "",
        error: str = "",
        error_description: str = "",
    ) -> Response:
        if error:
            detail = f"OpenID Provider returned an error: {error} {error_description}".strip()
            raise HTTPException(status_code=400, detail=detail)
        login_state = rp.state_store.pop(state, now=rp.clock())
        if login_state is None:
            raise HTTPException(status_code=400, detail="unknown or expired login state")
        if not code:
            raise HTTPException(status_code=400, detail="missing authorization code")
        # ... rest unchanged (complete_login -> on_authenticated) ...
```

(Der Rest des Handlers — `complete_login` im try/except `OidcError` → 401, dann `on_authenticated` — bleibt unverändert.)

- [ ] **Step 4: `CookieBackend.revoke` Cookie-Attribute**

In `src/fastapi_auth/openid/session/cookie.py` `revoke` anpassen, sodass `delete_cookie` dieselben Attribute wie `set_cookie` trägt:

```python
    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the server-side session and clear the cookie."""
        sid = self._read_sid(request)
        if sid is not None:
            await self._store.delete_session(sid)
        response.delete_cookie(
            self._settings.session_cookie_name,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )
```

- [ ] **Step 5: Tests grün laufen lassen**

Run: `uv run pytest tests/test_router.py tests/session/test_cookie.py -v`
Expected: alle passed. (Der bestehende `test_revoke_deletes_store_and_cookie` bleibt grün — `delete_cookie` setzt weiterhin `Max-Age=0`.)

- [ ] **Step 6: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/router.py src/fastapi_auth/openid/session/cookie.py tests/test_router.py
git commit -m "fix(oidc): /callback OP-error behandeln, Router-Negativpfade + revoke-Cookie-Attribute"
```

---

## Task 6: RP-initiated Logout

**Files:**
- Modify: `src/fastapi_auth/openid/router.py` (`/logout`-Route)
- Modify: `src/fastapi_auth/openid/rp.py` (Logout-Hilfslogik, EC `post_logout_redirect_uris`)
- Modify: `tests/oidc/conftest.py` (`OpFixture`: `end_session_endpoint`-Metadatum)
- Test: `tests/test_logout.py`

**Interfaces:**
- Consumes: `SessionBackend.revoke`/`load`, `resolve_and_validate`, `is_safe_redirect`.
- Produces:
  - Router `/logout?next=/`: lädt die Session-Identität (falls vorhanden), verwirft die Session (`backend.revoke`), und leitet weiter. Best-effort OP-Logout: wenn `settings.enable_op_logout`, die Identität ein `iss` hat, `settings.post_logout_redirect_uris` nicht leer ist, und `resolve_and_validate(iss)` ein `end_session_endpoint` liefert → Redirect dorthin mit `client_id`, `post_logout_redirect_uri` (erste registrierte), `state`. Jeder Fehler/fehlendes `end_session_endpoint` → lokaler Redirect auf `is_safe_redirect(next)` bzw. `post_logout_default`.
  - `router.py` well-known: die RP Entity Configuration veröffentlicht `post_logout_redirect_uris` in `metadata.openid_relying_party` (wenn konfiguriert).
  - `OpFixture.op_metadata` kann optional `end_session_endpoint` enthalten (für Tests).

- [ ] **Step 1: `OpFixture` um end_session erweitern**

In `tests/oidc/conftest.py` `OpFixture` um ein Flag/Feld erweitern, sodass `op_metadata()` optional `end_session_endpoint` einschließt. Beispiel: Feld `with_end_session: bool = False` und in `op_metadata()`:

```python
        provider = {
            "issuer": OP_ENTITY,
            "authorization_endpoint": f"{OP_ENTITY}/authorize",
            "token_endpoint": f"{OP_ENTITY}/token",
            "userinfo_endpoint": f"{OP_ENTITY}/userinfo",
            "jwks": jose.public_jwks(KeySet([self.protocol_key])),
        }
        if self.with_end_session:
            provider["end_session_endpoint"] = f"{OP_ENTITY}/logout"
        return {"openid_provider": provider}
```

(Bestehende Nutzung `OpFixture()` bleibt kompatibel — Default `with_end_session=False`.)

- [ ] **Step 2: Failing test schreiben**

`tests/test_logout.py`:

```python
"""Tests for RP-initiated logout (local + best-effort end_session)."""

import respx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from urllib.parse import parse_qs, urlparse

from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture


def _rp(op: OpFixture, **over) -> OidcRP:
    base = dict(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        cookie_secure=False,
    )
    base.update(over)
    return OidcRP(OidcSettings(**base), clock=lambda: NOW + 10)  # type: ignore[arg-type]


def _login(client: TestClient, op: OpFixture, rp: OidcRP, router: respx.Router) -> None:
    client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
    state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
    nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
    router.post(f"{OP_ENTITY}/token").respond(
        200, json={"access_token": "at", "id_token": op.id_token(nonce=nonce), "token_type": "Bearer"}
    )
    client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)


def test_local_logout_revokes_and_redirects():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)

    @app.get("/me")
    async def me(request):  # noqa: ANN001
        ident = await rp.backend.load(request)
        return JSONResponse({"authenticated": ident is not None})

    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        _login(client, op, rp, router)
        assert client.get("/me").json()["authenticated"] is True
        resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/bye"
        # session gone
        assert client.get("/me").json()["authenticated"] is False


def test_op_logout_redirects_to_end_session_when_enabled():
    op = OpFixture(with_end_session=True)
    rp = _rp(
        op,
        enable_op_logout=True,
        post_logout_redirect_uris=[f"{RP_ENTITY}/openid/post-logout"],
    )
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        _login(client, op, rp, router)
        resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith(f"{OP_ENTITY}/logout")
    q = parse_qs(urlparse(location).query)
    assert q["client_id"] == [RP_ENTITY]
    assert q["post_logout_redirect_uri"] == [f"{RP_ENTITY}/openid/post-logout"]


def test_logout_without_session_redirects_local():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/bye"


def test_well_known_publishes_post_logout_redirect_uris():
    op = OpFixture()
    rp = _rp(op, post_logout_redirect_uris=[f"{RP_ENTITY}/openid/post-logout"])
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    from fastapi_auth.openid.federation import jose

    resp = client.get("/openid/.well-known/openid-federation")
    claims = jose.verify_signature(resp.text, jose.load_keyset(jose.public_jwks(KeySet([op.rp_fed_key]))), algorithms=["RS256"])
    rp_meta = claims["metadata"]["openid_relying_party"]
    assert rp_meta["post_logout_redirect_uris"] == [f"{RP_ENTITY}/openid/post-logout"]
```

- [ ] **Step 3: Tests rot laufen lassen**

Run: `uv run pytest tests/test_logout.py -v`
Expected: FAIL (keine `/logout`-Route; EC ohne `post_logout_redirect_uris`).

- [ ] **Step 4: Logout-Hilfslogik in `OidcRP`**

In `src/fastapi_auth/openid/rp.py` eine best-effort-Logout-Hilfe ergänzen (nutzt `resolve_and_validate`):

```python
from urllib.parse import urlencode

from fastapi_auth.openid.federation.errors import FederationError
from fastapi_auth.openid.federation.trust_chain import resolve_and_validate
```

```python
    async def op_logout_url(self, identity: FederatedIdentity | None) -> str | None:
        """Best-effort end_session_endpoint URL for the identity's OP, or None.

        Returns None (→ local logout) unless op-logout is enabled, the identity
        carries an ``iss``, a post_logout_redirect_uri is registered, and the OP
        resolves to an ``end_session_endpoint``. Any federation failure falls
        back to a local logout (this must never block clearing the session).
        """
        if not self.settings.enable_op_logout or identity is None:
            return None
        issuer = identity.iss
        if not issuer or not self.settings.post_logout_redirect_uris:
            return None
        try:
            resolved = await resolve_and_validate(
                self.http_client,
                issuer,
                self.settings.trust_anchors,
                entity_type="openid_provider",
                leeway=self.settings.clock_skew,
                now=self.clock(),
            )
        except FederationError:
            # Best-effort logout: any resolution/validation failure → local logout.
            return None
        endpoint = resolved.metadata.get("end_session_endpoint")
        if not isinstance(endpoint, str):
            return None
        query = urlencode(
            {
                "client_id": self.settings.entity_id,
                "post_logout_redirect_uri": self.settings.post_logout_redirect_uris[0],
            }
        )
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{query}"
```

> **Umsetzungshinweis:** `except FederationError` deckt alle von `resolve_and_validate` geworfenen Fehler ab (`FetchError`/`TrustChainError`/`SignatureError`/`MetadataPolicyError` sind `FederationError`-Ableitungen) — kein breites `except Exception`/`# noqa: BLE001` nötig. Best-effort: bei Fehler wird `None` zurückgegeben und lokal ausgeloggt.

- [ ] **Step 5: Router `/logout` + EC `post_logout_redirect_uris`**

In `src/fastapi_auth/openid/router.py` die well-known-EC-Metadaten um `post_logout_redirect_uris` ergänzen (im `/.well-known`-Handler, wo `rp_metadata` gebaut wird):

```python
        if settings.post_logout_redirect_uris:
            rp_metadata.setdefault("post_logout_redirect_uris", settings.post_logout_redirect_uris)
```

Und die `/logout`-Route ergänzen:

```python
    @router.get("/logout")
    async def logout(request: Request, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, settings.allowed_redirect_hosts)
        identity = await rp.backend.load(request)
        op_url = await rp.op_logout_url(identity)
        target = op_url if op_url is not None else safe_next
        response = RedirectResponse(target, status_code=303)
        await rp.backend.revoke(request, response)
        return response
```

- [ ] **Step 6: Tests grün laufen lassen**

Run: `uv run pytest tests/test_logout.py -v`
Expected: alle passed. (Falls der `end_session`-Test scheitert, prüfe, dass `OpFixture(with_end_session=True)` das Endpoint-Feld in `op_metadata()` setzt und `resolve_and_validate` es in `resolved.metadata` durchreicht.)

- [ ] **Step 7: Lint + ganze Suite**

Run: `uv run pytest -q && make lint`
Expected: grün; exit 0.

- [ ] **Step 8: Commit**

```bash
git add src/fastapi_auth/openid/router.py src/fastapi_auth/openid/rp.py tests/oidc/conftest.py tests/test_logout.py
git commit -m "feat(oidc): RP-initiated Logout (lokal + best-effort end_session_endpoint)"
```

---

## Task 7: End-to-End + Finalisierung

**Files:**
- Test: `tests/test_discovery_flow.py` (End-to-End: WAYF-Seite → Auswahl → Login → Session; Logout)
- Modify (optional): `src/fastapi_auth/openid/__init__.py` (nichts Neues zwingend zu re-exportieren; prüfen)

**Interfaces:**
- Keine neue Logik — ein End-to-End-Test, der die WAYF-Auswahl mit dem Login-Flow (Plan 3) und der Session (Plan 4) verbindet, plus Logout.

- [ ] **Step 1: Failing/Integration-Test schreiben**

`tests/test_discovery_flow.py`:

```python
"""End-to-end: embedded WAYF selection drives login into a session; logout clears it."""

import re

import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture


def _rp(op: OpFixture) -> OidcRP:
    settings = OidcSettings(  # type: ignore[arg-type]
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        cookie_secure=False,
        discovery_mode="embedded",
        op_list=[{"entity_id": OP_ENTITY, "display_name": "Example OP"}],
    )
    return OidcRP(settings, clock=lambda: NOW + 10)


def test_wayf_selection_logs_in_then_logout():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)

    @app.get("/me")
    async def me(user: FederatedIdentity = Depends(rp.current_user())):  # noqa: B008
        return {"sub": user.sub}

    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        # 1. WAYF page lists the OP; extract the login link's op param
        wayf = client.get("/openid/login?next=/app", follow_redirects=False)
        assert wayf.status_code == 200
        assert "Example OP" in wayf.text
        # 2. follow the selection (explicit op) -> redirect to OP
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
        nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
        router.post(f"{OP_ENTITY}/token").respond(
            200, json={"access_token": "at", "id_token": op.id_token(nonce=nonce), "token_type": "Bearer"}
        )
        # 3. callback establishes session
        client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
        assert client.get("/me").status_code == 200
        # 4. logout clears it
        client.get("/openid/logout?next=/bye", follow_redirects=False)
        assert client.get("/me").status_code == 401
```

- [ ] **Step 2: Test laufen lassen**

Run: `uv run pytest tests/test_discovery_flow.py -v`
Expected: passed (bestätigt die Integration von WAYF → Login → Session → Logout). Falls rot: ein realer Integrationsfehler — melden.

- [ ] **Step 3: Ganze Suite + Lint**

Run:

```bash
uv run pytest
uv run ruff format .
uv run ruff check .
uv run ty check src tests
make lint
```

Expected: pytest alle passed (Plan 1–5); ruff „All checks passed!"; `ty` ohne Fehler; `make lint` exit 0. Doku-Markdown-Churn aus `ruff format .` NICHT committen (nur `src`/`tests`).

- [ ] **Step 4: Commit**

```bash
git add tests/test_discovery_flow.py
git commit -m "test(discovery): End-to-End WAYF-Auswahl -> Login -> Session -> Logout"
```

---

## Self-Review

**Spec-Abdeckung (Plan 5 vs. Design §5 + Roadmap Plan 5):**
- Discovery-/Logout-Settings + jinja2 → Task 1 ✅
- Federation-List-Endpoint-Helper (§8.2) → Task 2 ✅
- Eingebetteter WAYF-Renderer (Jinja2 autoescape) → Task 3 ✅
- `/login`-Discovery (passthrough/embedded/`?op`) → Task 4 ✅
- Offene Cleanups aus Plan 3/4: `/callback`-OP-Fehler, Router-Negativpfade, `revoke`-Cookie-Attribute → Task 5 ✅
- RP-initiated Logout (lokal + best-effort `end_session_endpoint`, EC `post_logout_redirect_uris`) → Task 6 ✅
- End-to-End WAYF→Login→Session→Logout → Task 7 ✅

**Bewusst NICHT (dokumentiert):** dynamisches WAYF-Listing im Router (Helper gebaut, nicht verdrahtet), `id_token_hint` beim Logout, Front-/Back-Channel-Logout, Docker/CI/Doku (Plan 6). Kein stiller Skip.

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt enthält vollständigen Code + exakte Kommandos. Zwei Umsetzungshinweise (Template-Package-Data; `except FederationError` statt breitem `except`) sind als verbindliche Entscheidungen ausformuliert.

**Typ-Konsistenz:** Settings-Discovery/Logout-Felder (T1) ⇄ `fetch.list_subordinates` (T2) ⇄ `discovery.embedded` (`OpChoice`/`render_wayf`, T3) ⇄ Router `/login` + `OidcRP.op_choices`/`jinja_env` (T4) ⇄ `/callback`/`revoke` (T5) ⇄ `/logout` + `OidcRP.op_logout_url` (T6) ⇄ E2E (T7). Der `OpFixture`-Testhelfer (`with_end_session`) wird von T6/T7 genutzt.

**Sicherheits-Selbstprüfung:** WAYF-Jinja-Env `autoescape` an (Escape-Test in T3); `next`/`post_logout_redirect_uri`-Rücksprünge via `is_safe_redirect`; `?op` triggert vollständige `resolve_and_validate`-Vertrauensprüfung beim Login (kein Trust ohne Trust-Chain); Logout ist best-effort und failt immer sicher lokal; EC registriert `post_logout_redirect_uris` (OP-seitige Redirect-Validierung); keine Secrets im Log.

---

## Nächster Meilenstein

- **Plan 6 — Docker/CI/Doku:** `Dockerfile` (Multi-Stage, slim) + `compose.yml` (Redis/Postgres für
  Integrationstests), `make test-integration`, GitHub Actions (ruff + ty + pytest/tox-Matrix +
  Docker-Build), Sphinx/MyST-Doku (Diataxis: Föderations-Login-Tutorial, How-tos, Reference,
  Explanation) nach dem `plone-doc-style`-Skill.
