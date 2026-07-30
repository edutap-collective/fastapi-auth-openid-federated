# Plan 6 — Docker/CI/Doku (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Package produktionsreif verpacken und dokumentieren: eine schlanke Docker-Test-Umgebung
(`Dockerfile` + `compose.yml` mit Redis/Postgres), echte Integrationstests (`make test-integration`),
git-basierte CI (GitHub Actions: ruff + ty + pytest/tox-Matrix + Docker-Build + Docs-Build) sowie
Sphinx/MyST-Dokumentation (Diataxis: Tutorial, How-tos, Reference, Explanation). Dabei die drei aus
Plan 5 geparkten Config-Kleinigkeiten schließen.

**Architecture:** **Gespiegelt vom SAML-Package** (`fastapi-auth-saml-federated`), aber **schlanker** —
dieses Paket hat **keine System-Dependency** (JOSE statt XML, kein `xmlsec1`), also ein einfacherer
Dockerfile und einfacheres CI (kein `apt-get install xmlsec1`). Integrationstests laufen gegen echte
Redis/Postgres aus `compose.yml`, gesteuert über die Umgebungsvariablen `IT_REDIS_URL`/`IT_DB_URL` und
den pytest-Marker `integration` (per Default via `-m 'not integration'` übersprungen). Doku ist
Sphinx + MyST (Furo-Theme), Struktur nach Diataxis. Kein produktiver Auth-Code in diesem Plan —
Packaging, Betrieb und Dokumentation.

**Tech Stack:** Docker (multi-stage, `python:3.13-slim`), uv, tox (`tox-uv`, Py 3.12/3.13/3.14),
GitHub Actions, Sphinx + MyST + Furo, ruff, ty, pytest. Redis 7 / Postgres 17 (compose).

## Global Constraints

- Distribution: `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header in **jeder** Quellcodedatei unter `src/` (inkl. `docs/conf.py`).
- Python-Floor: `>=3.12`. Support-Fenster: Py 3.12/3.13/3.14 (alle im Support; endoflife.date). Basis-Images/Dienste auf unterstützten Ständen (Redis 7, Postgres 17, python:3.13-slim).
- Sprache: Code/Kommentare/Docstrings **Englisch**. **Doku & Commit-Messages: Deutsch** (LMU-Kontext), Conventional Commits. Doku folgt dem `plone-doc-style`-Skill (Diataxis, MyST).
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren. `make lint` (scoped `src tests`) MUSS exit 0.
- **Wichtig (aus Plan-1-Erfahrung):** `ruff format --check .` (ganzes Repo) reformatiert eingebettete Python-Code-Fences in Markdown und schlägt an den SDD-Plan-Dateien fehl. Alle Lint-Kommandos (Makefile, tox `lint`, CI) MÜSSEN auf `src tests` gescoped bleiben — **niemals `ruff check .`/`ruff format --check .`** in CI/tox.
- Kein selbstgebautes JOSE/Krypto (unverändert; dieser Plan berührt keinen Krypto-Code).
- Docker: kleine Images (multi-stage, `-slim`); nur nötige Artefakte ins finale Image. Docker-Nutzung in `README.md` **und** `docs/` dokumentieren.
- CI spiegelt lokal: ruff (check + format) + ty + pytest über die tox-Matrix; zusätzlich Docker-Image-Build + Docs-Build.
- Niemals `git push`. Commits auf `main` sind für dieses greenfield-Repo ausdrücklich erlaubt.
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).

### Umgebung (verifiziert)

- **Docker ist verfügbar** (29.6.2) → `docker build` / `docker compose config` sind in den Tasks ausführbar. Image-Pulls (python:3.13-slim, redis, postgres) brauchen Netz; falls ein Pull in der Ausführungsumgebung scheitert, den Build/Compose per Inspektion + `docker compose config` (Syntax) validieren und im Report vermerken — der reale Lauf passiert in CI/lokal.
- **Sphinx/MyST/Furo sind NICHT installiert** → über das neue `docs`-Extra (`uv pip install -e ".[docs]"`) bereitstellen und `sphinx-build -W` zum Verifizieren nutzen.
- Referenz-Templates: `~/workspaces/LMU/wallet/fastapi-auth-saml-federated/{Dockerfile,compose.yml,tox.ini,.github/workflows/ci.yml,docs/}`.

## File Structure

```text
pyproject.toml                     # docs-Extra; integration-Marker; include-package-data korrekt platzieren
Makefile                           # test-integration: echte compose-basierte Läufe
Dockerfile                         # multi-stage slim (KEIN xmlsec1)
.dockerignore
compose.yml                        # redis + postgres (Integrationstests)
tox.ini                            # py312/313/314 + lint (scoped src tests)
.github/workflows/ci.yml           # test-Matrix + integration + docker + docs
src/fastapi_auth/openid/router.py  # /logout: post_logout_default verdrahten (Plan-5-Minor)
tests/session/test_stores_integration.py  # @integration: echte Redis/Postgres via IT_-Env
tests/test_logout.py               # + post_logout_default-Test (bestehende Datei)
docs/conf.py
docs/index.md
docs/tutorial/federation-login.md
docs/howto/{trust-anchors,fed-keys,stores,wayf,docker,logout}.md
docs/reference/{settings,identity,public-api}.md
docs/explanation/{trust-chain,security-model}.md
README.md                          # Nutzung, Docker, Docs-Links
```

---

## Task 1: Packaging-Cleanups + Integration-Marker + docs-Extra + post_logout_default

**Files:**
- Modify: `pyproject.toml`, `src/fastapi_auth/openid/router.py`, `tests/test_logout.py`

**Interfaces:**
- `pyproject.toml`: `include-package-data = true` von `[build-system]` nach `[tool.setuptools]` verschieben; `docs`-Extra ergänzen; pytest `integration`-Marker + `addopts = "-ra -m 'not integration'"`.
- `/logout`: `next: str | None = None`; fehlt `next`, wird `settings.post_logout_default` als lokales Ziel genutzt (schließt den Plan-5-Minor „post_logout_default ungenutzt").

- [ ] **Step 1: Failing test schreiben**

An `tests/test_logout.py` anhängen:

```python
def test_logout_uses_post_logout_default_when_no_next():
    op = OpFixture()
    rp = _rp(op, post_logout_default="/goodbye")
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/logout", follow_redirects=False)  # no ?next
    assert resp.status_code == 303
    assert resp.headers["location"] == "/goodbye"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_logout.py::test_logout_uses_post_logout_default_when_no_next -v`
Expected: FAIL (aktuell Default `next="/"` → Redirect nach `/`, nicht `/goodbye`).

- [ ] **Step 3: `/logout` post_logout_default verdrahten**

In `src/fastapi_auth/openid/router.py` den `/logout`-Handler anpassen, sodass ein fehlendes `next` auf `settings.post_logout_default` fällt:

```python
    @router.get("/logout")
    async def logout(request: Request, next: str | None = None) -> Response:
        target_next = next if next is not None else settings.post_logout_default
        safe_next = is_safe_redirect(target_next, settings.allowed_redirect_hosts)
        identity = await rp.backend.load(request)
        op_url = await rp.op_logout_url(identity)
        target = op_url if op_url is not None else safe_next
        response = RedirectResponse(target, status_code=303)
        await rp.backend.revoke(request, response)
        return response
```

- [ ] **Step 4: pyproject aufräumen + docs-Extra + integration-Marker**

In `pyproject.toml`:

1. `include-package-data = true` aus `[build-system]` **entfernen** und unter `[tool.setuptools]` setzen. Falls es keine `[tool.setuptools]`-Sektion gibt, direkt vor `[tool.setuptools.packages.find]` einfügen:

```toml
[tool.setuptools]
include-package-data = true
```

2. In `[project.optional-dependencies]` das `docs`-Extra ergänzen:

```toml
docs = ["sphinx>=7", "myst-parser>=3", "furo>=2024.0"]
```

3. `[tool.pytest.ini_options]` erweitern (Marker + Default-Deselect von Integrationstests):

```toml
[tool.pytest.ini_options]
addopts = "-ra -m 'not integration'"
testpaths = ["tests"]
asyncio_mode = "auto"
pythonpath = ["."]
markers = ["integration: needs live redis/postgres (make test-integration)"]
```

Dann `uv pip install -U -e ".[dev,docs]"`.

- [ ] **Step 5: Tests grün + Lint + Wheel-Check**

Run:

```bash
uv run pytest -q
make lint
uv build --wheel 2>/dev/null && uv run python - <<'PY'
import zipfile, glob
whl = sorted(glob.glob("dist/*.whl"))[-1]
names = zipfile.ZipFile(whl).namelist()
assert any(n.endswith("discovery/templates/wayf.html") for n in names), "template missing from wheel"
assert any(n.endswith("openid/py.typed") for n in names), "py.typed missing"
print("wheel ships template + py.typed")
PY
```

Expected: pytest alle passed (Default ohne Integrationstests); `make lint` exit 0; „wheel ships template + py.typed". (`dist/` nicht committen — es ist git-ignoriert bzw. mit `git checkout -- .`/`rm -rf dist` aufräumen.)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/fastapi_auth/openid/router.py tests/test_logout.py
git commit -m "chore(build): docs-Extra, integration-Marker, include-package-data korrekt platzieren, post_logout_default verdrahten"
```

---

## Task 2: Dockerfile + .dockerignore

**Files:**
- Create: `Dockerfile`, `.dockerignore`

**Interfaces:**
- Multi-stage (`build` → `runtime`), `python:3.13-slim`, `uv` für Installation, **kein `xmlsec1`/apt** (keine System-Dependency). Import-Smoke-Check im Build. `CMD` gibt Version aus.

- [ ] **Step 1: `.dockerignore` anlegen**

```text
.git
.venv
dist
build
*.egg-info
__pycache__
.superpowers
docs/_build
.tox
.ruff_cache
.pytest_cache
```

- [ ] **Step 2: `Dockerfile` anlegen**

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
COPY pyproject.toml README.md ./
COPY src ./src
# No system dependency: JOSE (joserfc), not XML — no xmlsec1 needed.
RUN uv pip install --system --no-cache ".[redis,postgres]"
RUN rm -f /usr/local/bin/uv

FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
WORKDIR /app
# Smoke check baked in: the package imports cleanly.
RUN python -c "from fastapi_auth import openid; print('import ok', openid.__version__)"
CMD ["python", "-c", "from fastapi_auth import openid; print('fastapi-auth-openid-federated', openid.__version__)"]
```

- [ ] **Step 3: Build verifizieren**

Run: `docker build -t fa-openid:plan6 . && docker run --rm fa-openid:plan6`
Expected: Build erfolgreich; `docker run` gibt `fastapi-auth-openid-federated 0.1.0.dev0` aus. (Falls ein Image-Pull in der Umgebung scheitert: `docker build` trotzdem versuchen; bei Netzwerkfehler den Dockerfile per Inspektion validieren und im Report vermerken — der Build läuft in CI.)

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat(docker): schlankes Multi-Stage-Image (kein xmlsec1, JOSE-only)"
```

---

## Task 3: compose.yml + Integrationstests + `make test-integration`

**Files:**
- Create: `compose.yml`, `tests/session/test_stores_integration.py`
- Modify: `Makefile` (`test-integration`)

**Interfaces:**
- `compose.yml`: `redis:7-alpine` (6379) + `postgres:17-alpine` (5432) mit Healthchecks.
- `tests/session/test_stores_integration.py`: `@pytest.mark.integration`; nutzt `IT_REDIS_URL`/`IT_DB_URL` (via `os.environ`), `pytest.mark.skipif` wenn nicht gesetzt; testet `RedisStore.from_url` und `PostgresStore.from_url` gegen echte Dienste (Session-Roundtrip).
- `Makefile test-integration`: compose up (wait healthy) → `pytest -m integration` mit `IT_`-Env → compose down.

- [ ] **Step 1: `compose.yml` anlegen**

```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 20
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_PASSWORD: pw
      POSTGRES_DB: fa
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 2s
      timeout: 3s
      retries: 20
```

- [ ] **Step 2: Integrationstests schreiben**

`tests/session/test_stores_integration.py`:

```python
"""Integration tests for the optional stores against live Redis/Postgres.

Skipped unless IT_REDIS_URL / IT_DB_URL are set (see `make test-integration`).
"""

import os

import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.postgres_store import PostgresStore
from fastapi_auth.openid.session.redis_store import RedisStore

pytestmark = pytest.mark.integration

_REDIS_URL = os.environ.get("IT_REDIS_URL")
_DB_URL = os.environ.get("IT_DB_URL")


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.skipif(_REDIS_URL is None, reason="IT_REDIS_URL not set")
@pytest.mark.asyncio
async def test_redis_store_live_round_trip():
    store = RedisStore.from_url(_REDIS_URL)
    try:
        await store.save_session("it-sid", _identity(), ttl=60)
        loaded = await store.load_session("it-sid")
        assert loaded is not None
        assert loaded.sub == "u1"
        await store.delete_session("it-sid")
        assert await store.load_session("it-sid") is None
    finally:
        await store.aclose()


@pytest.mark.skipif(_DB_URL is None, reason="IT_DB_URL not set")
@pytest.mark.asyncio
async def test_postgres_store_live_round_trip():
    store = PostgresStore.from_url(_DB_URL)
    try:
        await store.create_all()
        await store.save_session("it-sid", _identity(), ttl=60)
        loaded = await store.load_session("it-sid")
        assert loaded is not None
        assert loaded.mail == ["u@lmu.de"]
        await store.delete_session("it-sid")
    finally:
        await store.aclose()
```

- [ ] **Step 3: `Makefile` `test-integration` ersetzen**

```make
test-integration:
	docker compose up -d --wait
	IT_REDIS_URL=redis://localhost:6379/0 \
	IT_DB_URL=postgresql+asyncpg://postgres:pw@localhost:5432/fa \
	uv run pytest -m integration -v; \
	status=$$?; \
	docker compose down -v; \
	exit $$status
```

- [ ] **Step 4: Verifizieren**

Run:

```bash
docker compose config >/dev/null && echo "compose valid"
uv run pytest -m integration --collect-only -q
uv run pytest -q   # default run: integration deselected, must stay green
make lint
```

Expected: „compose valid"; `--collect-only` listet die 2 Integrationstests; der Default-Lauf (`pytest -q`) überspringt sie (`-m 'not integration'`) und bleibt grün; `make lint` exit 0.

Optional (wenn Docker-Pull möglich): `make test-integration` → beide Integrationstests passed. Falls Image-Pull scheitert: im Report vermerken, `docker compose config` + `--collect-only` genügen als Verifikation in der Ausführungsumgebung.

- [ ] **Step 5: Commit**

```bash
git add compose.yml tests/session/test_stores_integration.py Makefile
git commit -m "feat(compose): Redis/Postgres-Integrationstests + make test-integration"
```

---

## Task 4: tox.ini + GitHub Actions CI

**Files:**
- Create: `tox.ini`, `.github/workflows/ci.yml`

**Interfaces:**
- `tox.ini`: `env_list = py312, py313, py314, lint`; `tox-uv`-Runner; `[testenv]` läuft `pytest -m "not integration"`; `[testenv:lint]` läuft `ruff check src tests`, `ruff format --check src tests`, `ty check src tests` (**scoped**, nie `.`).
- `.github/workflows/ci.yml`: Jobs `test` (Matrix 3.12/3.13/3.14, **kein xmlsec1**), `integration` (redis/postgres services, `IT_`-Env), `docker` (`docker build`), `docs` (`sphinx-build -W`).

- [ ] **Step 1: `tox.ini` anlegen**

```ini
[tox]
env_list = py312, py313, py314, lint
skip_missing_interpreters = true
requires = tox-uv>=1.13

[testenv]
runner = uv-venv-runner
extras = dev
commands = pytest -m "not integration" {posargs}

[testenv:lint]
extras = dev
commands =
    ruff check src tests
    ruff format --check src tests
    ty check src tests
```

- [ ] **Step 2: `.github/workflows/ci.yml` anlegen**

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ["3.12", "3.13", "3.14"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv python install ${{ matrix.python }}
      - run: uv pip install --system -e ".[dev]"
      - run: ruff check src tests
      - run: ruff format --check src tests
      - run: ty check src tests
      - run: pytest -m "not integration"
  integration:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: >-
          --health-cmd "redis-cli ping" --health-interval 2s --health-timeout 3s --health-retries 20
      postgres:
        image: postgres:17-alpine
        env: { POSTGRES_PASSWORD: pw, POSTGRES_DB: fa }
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 2s --health-timeout 3s --health-retries 20
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv pip install --system -e ".[dev,redis,postgres]"
      - run: pytest -m integration
        env:
          IT_REDIS_URL: redis://localhost:6379/0
          IT_DB_URL: postgresql+asyncpg://postgres:pw@localhost:5432/fa
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t fa-openid:ci .
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv pip install --system -e ".[docs]"
      - run: uv run sphinx-build -W -b html docs docs/_build
```

- [ ] **Step 3: Verifizieren**

Run:

```bash
uvx --from tox --with tox-uv tox -l 2>/dev/null || uvx tox -l
uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml valid yaml')"
```

Expected: `tox -l` listet `py312 py313 py314 lint`; „ci.yml valid yaml". (Falls `tox`/`pyyaml` nicht verfügbar: `uvx tox -l` bzw. YAML per `uv run python -c "import tomllib"`-Analog; im Report vermerken. `tox`-Läufe selbst laufen in CI, nicht hier.)

- [ ] **Step 4: Commit**

```bash
git add tox.ini .github/workflows/ci.yml
git commit -m "ci: tox-Matrix (py312/313/314) + GitHub Actions (test/integration/docker/docs)"
```

---

## Task 5: Sphinx-Doku-Gerüst + Reference + Explanation

**Files:**
- Create: `docs/conf.py`, `docs/index.md`, `docs/reference/{settings,identity,public-api}.md`, `docs/explanation/{trust-chain,security-model}.md`

> **Umsetzungshinweis (verbindlich):** Für die Doku-Prosa das **`plone-doc-style`-Skill** befolgen (Diataxis-Quadranten, MyST-Markup, Ton). Dieser Task deckt **Reference** (faktisch, nachschlagbar) und **Explanation** (Verständnis/Hintergrund) ab. Die Doku ist **Deutsch** (LMU-Kontext), Code/Bezeichner/Identifier bleiben Englisch. Halte die Reference eng an den tatsächlichen Feldern/Signaturen (`OidcSettings`, `FederatedIdentity`, `OidcRP`, Claim-Registry) — verifiziere jede genannte Option gegen den Code.

**Interfaces:** reine Dokumentation; Verifikation über `sphinx-build -W` (keine Warnungen).

- [ ] **Step 1: `docs/conf.py` anlegen**

```python
"""Sphinx configuration for the fastapi-auth-openid-federated documentation.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

project = "fastapi-auth-openid-federated"
author = "Alexander Loechel"
copyright = f"2026, {author}"  # noqa: A001 - Sphinx-mandated config name

extensions = ["myst_parser"]

source_suffix = {".md": "markdown"}

# `docs/superpowers/` holds the internal SDD planning artifacts (specs, plans,
# task briefs). They are not part of the published documentation.
exclude_patterns = ["_build", "superpowers", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
```

- [ ] **Step 2: `docs/index.md` + Toctree anlegen**

`docs/index.md` mit einer kurzen Einleitung (föderierter OIDC-RP, `fastapi_auth.openid`) und einem MyST-Toctree, der Tutorial/How-to/Reference/Explanation einbindet. Beispiel-Grundgerüst (Prosa per `plone-doc-style` ausbauen):

````markdown
# fastapi-auth-openid-federated

Föderierter OpenID-Connect-Relying-Party als FastAPI-Baustein — Vertrauen zu OpenID
Providern über **OpenID Federation 1.0**.

```{toctree}
:maxdepth: 2
:caption: Inhalt

tutorial/federation-login
howto/trust-anchors
howto/fed-keys
howto/stores
howto/wayf
howto/logout
howto/docker
reference/settings
reference/identity
reference/public-api
explanation/trust-chain
explanation/security-model
```
````

(Die `howto/`- und `tutorial/`-Dateien entstehen in Task 6; damit `sphinx-build -W` in **diesem** Task nicht an fehlenden Toctree-Zielen scheitert, lege in Task 5 leere Platzhalter-Stubs für die in Task 6 zu füllenden Dateien an — je eine `# Titel`-Zeile —, ODER nimm die `tutorial/`/`howto/`-Einträge erst in Task 6 in den Toctree auf. **Umsetzungsentscheidung:** In Task 5 nur die in Task 5 erstellten Dateien in den Toctree aufnehmen; Tutorial/How-tos werden in Task 6 ergänzt. Passe den Toctree entsprechend an, sodass `sphinx-build -W` in Task 5 warnungsfrei ist.)

- [ ] **Step 3: Reference-Seiten schreiben**

- `docs/reference/settings.md` — alle `OidcSettings`-Felder mit Typ/Default/Zweck (Entity/Keys, Trust-Anchors, `authority_hints`, Scopes, `id_token_signing_alg_values`, Discovery, Logout, Session/Store/JWT, Lifetimes/Skew, Security). **Gegen den Code verifizieren.**
- `docs/reference/identity.md` — `FederatedIdentity`-Felder + Claim-Registry (OIDC + eduPerson-via-OIDC Mapping-Tabelle), `map_claims`, `select_identifier`.
- `docs/reference/public-api.md` — `from fastapi_auth import openid`: `OidcRP`, `OidcSettings`, `FederatedIdentity`, `map_claims`, `select_identifier`, `SessionBackend`, `Store`; die Router-Endpunkte (`/.well-known/openid-federation`, `/openid/login`, `/openid/callback`, `/openid/logout`); `current_user`/`optional_user`.

- [ ] **Step 4: Explanation-Seiten schreiben**

- `docs/explanation/trust-chain.md` — Trust-Chain-Auflösung + Validierung, Metadata-Policy, warum kein Trust ohne konfigurierten Anchor (Verweis auf Plan-2-Modell).
- `docs/explanation/security-model.md` — Sicherheitsmodell: Algorithmus-Pinning, PKCE/state/nonce, Request-Object-`aud`=OP-Entity-ID, ID-Token-Validierung gegen Trust-Chain-JWKS, Session-Cookie-Härtung, Open-Redirect-Guard, WAYF-Autoescape, best-effort Logout.

- [ ] **Step 5: Doku bauen (warnungsfrei)**

Run:

```bash
uv pip install -U -e ".[docs]"
uv run sphinx-build -W -b html docs docs/_build
```

Expected: Build ohne Warnungen/Fehler (`-W` macht Warnungen zu Fehlern). `docs/_build` NICHT committen (in `.gitignore`/`.dockerignore` bereits ausgeschlossen; sonst `docs/_build` ignorieren).

- [ ] **Step 6: Commit**

```bash
git add docs/conf.py docs/index.md docs/reference docs/explanation
git commit -m "docs: Sphinx-Gerüst + Reference (Settings/Identity/API) + Explanation (Trust-Chain/Security)"
```

---

## Task 6: Tutorial + How-tos

**Files:**
- Create: `docs/tutorial/federation-login.md`, `docs/howto/{trust-anchors,fed-keys,stores,wayf,docker,logout}.md`
- Modify: `docs/index.md` (Tutorial/How-tos in den Toctree aufnehmen)

> **Umsetzungshinweis (verbindlich):** `plone-doc-style`-Skill befolgen. **Tutorial** = lernorientiert (ein durchgehender, funktionierender Föderations-Login-Durchlauf). **How-to** = aufgabenorientiert (je ein konkretes Problem lösen). Deutsch; Code/Bezeichner Englisch. Alle Code-Beispiele gegen die tatsächliche API (`OidcRP`/`OidcSettings`) prüfen.

- [ ] **Step 1: Tutorial schreiben**

`docs/tutorial/federation-login.md` — Schritt-für-Schritt: minimale FastAPI-App, `OidcSettings` (entity_id, base_url, fed_jwks, authority_hints, trust_anchors), `OidcRP` mounten, geschützte Route mit `Depends(rp.current_user())`, Login über `/openid/login?op=...`. End-to-End nachvollziehbar.

- [ ] **Step 2: How-tos schreiben**

- `docs/howto/trust-anchors.md` — Trust Anchors konfigurieren (`trust_anchors`, out-of-band-Keys), `authority_hints`.
- `docs/howto/fed-keys.md` — RP-Federation-Keys (`fed_jwks`) erzeugen/rollen; die veröffentlichte Entity Configuration.
- `docs/howto/stores.md` — Session-Backend (cookie/jwt) + Store (memory/redis/postgres) wählen; Redis/Postgres-Extras.
- `docs/howto/wayf.md` — Discovery: feste OP (passthrough) vs. embedded WAYF (`op_list`).
- `docs/howto/logout.md` — RP-initiated Logout (lokal + `enable_op_logout`/`post_logout_redirect_uris`/`end_session_endpoint`).
- `docs/howto/docker.md` — Docker-Umgebung: Image bauen/laufen, `compose.yml`, `make test-integration`, Teardown. (Betont: **keine** System-Dependency, schlankeres Image als SAML.)

- [ ] **Step 3: Toctree ergänzen + Doku bauen**

`docs/index.md`-Toctree um die Tutorial/How-to-Einträge erweitern (falls in Task 5 noch nicht enthalten).

Run: `uv run sphinx-build -W -b html docs docs/_build`
Expected: Build ohne Warnungen/Fehler; alle Toctree-Ziele existieren.

- [ ] **Step 4: Commit**

```bash
git add docs/tutorial docs/howto docs/index.md
git commit -m "docs: Tutorial (Föderations-Login) + How-tos (Trust-Anchors/Keys/Stores/WAYF/Logout/Docker)"
```

---

## Task 7: README + Finalisierung

**Files:**
- Modify: `README.md`

**Interfaces:** README als Einstieg — Kurzbeschreibung, Install, Minimal-Usage (`OidcRP`), Docker-Kurzhinweis, Verweis auf `docs/`, Lizenz.

- [ ] **Step 1: `README.md` erweitern**

Den bestehenden README um Abschnitte ergänzen (Prosa knapp, Deutsch/Englisch gemischt wie bisher): Kurzbeschreibung (föderierter OIDC-RP), **Quickstart** (`OidcSettings` + `OidcRP.mount(app)` + `Depends(rp.current_user())`), **Docker** (`docker build`/`docker run`, `make test-integration`), **Dokumentation** (Verweis auf `docs/` + Diataxis-Struktur, Build via `.[docs]` + `sphinx-build`), **CI** (GitHub Actions: ruff/ty/pytest-Matrix/docker/docs). Lizenzabschnitt beibehalten.

- [ ] **Step 2: Gesamt-Verifikation**

Run:

```bash
uv run pytest -q
make lint
uv run sphinx-build -W -b html docs docs/_build
docker compose config >/dev/null && echo "compose valid"
```

Expected: pytest alle passed; `make lint` exit 0; Docs-Build warnungsfrei; „compose valid". (Doku-Markdown-Churn aus etwaigem `ruff format .` NICHT committen — Lint bleibt auf `src tests` gescoped.)

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): Quickstart, Docker, Doku- und CI-Hinweise"
```

---

## Self-Review

**Spec-Abdeckung (Plan 6 vs. Design §7/§9 + Roadmap Plan 6):**
- Docker-Test-Umgebung (`Dockerfile` schlank ohne xmlsec1 + `.dockerignore`) → Task 2 ✅
- `compose.yml` (Redis/Postgres) + `make test-integration` + Integrationstests → Task 3 ✅
- CI: tox-Matrix (py312/313/314) + GitHub Actions (test/integration/docker/docs) → Task 4 ✅
- Sphinx/MyST-Doku (Diataxis): Reference + Explanation → Task 5; Tutorial + How-tos → Task 6 ✅
- README (Nutzung, Docker, Doku) → Task 7 ✅
- Geparkte Plan-5-Minors: `include-package-data` korrekt platziert (T1), `post_logout_default` verdrahtet (T1). Der dritte („`logout_path` validation-only") ist konsistent mit `redirect_path` und bleibt bewusst so (dokumentierter Verzicht, kein toter Code — es validiert eine reale Constraint).

**Bewusst NICHT (dokumentiert):** dynamisches WAYF-Listing, `id_token_hint`, Front-/Back-Channel-Logout (Folgepläne). PyPI-Publish-Workflow (Release-CI) außerhalb dieses Plans.

**Platzhalter-Scan:** kein TBD/TODO im Infra-Code; jeder Infra-Schritt enthält vollständige Datei-Inhalte + exakte Verifikationskommandos. Doku-Tasks nennen konkrete Dateien, Diataxis-Quadranten und Inhaltsgerüste; die Prosa wird per `plone-doc-style`-Skill ausgeführt (verbindlicher Umsetzungshinweis).

**Typ-/Struktur-Konsistenz:** Der `integration`-Marker (T1 pyproject) ⇄ Integrationstests (T3) ⇄ `make test-integration`/CI-`IT_`-Env (T3/T4). Der `docs`-Extra (T1) ⇄ `sphinx-build` (T5/T6/T4-CI). Der Dockerfile (`.[redis,postgres]`, T2) ⇄ compose-Dienste (T3). Alle Lint-Kommandos (Makefile/tox/CI) sind konsistent auf `src tests` gescoped (nie `.`), gemäß der Plan-1-Erfahrung.

**Sicherheits-/Betriebs-Selbstprüfung:** schlankes Multi-Stage-Image (nur site-packages im Runtime-Layer), Import-Smoke-Check im Build; keine Secrets in Dockerfile/compose/CI (nur Test-Passwörter für lokale/CI-Postgres); Basis-Images/Dienste auf unterstützten Ständen; CI spiegelt lokale Checks.

---

## Roadmap-Abschluss

Mit Plan 6 ist die v1-Roadmap (Pläne 1–6) vollständig: Fundament/Identität, Federation-Entity-Core,
OIDC-Login, Session-Backends, Discovery/WAYF+Logout, Docker/CI/Doku. Offene v1.1+-Themen (explicit
client registration, Trust-Mark-Enforcement, RP-Logout mit `id_token_hint`, Metadaten-/Trust-Chain-
Auto-Refresh, dynamisches WAYF-Listing, `fastapi-auth-core`-Extraktion) sind in der Design-Spec §10
als spätere Meilensteine dokumentiert.
