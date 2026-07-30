# Plan 3 — OIDC-Login (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auf der Federation-Vertrauensschicht (Plan 2) den vollständigen OpenID-Connect-Login als
FastAPI-Baustein aufsetzen: Authorization-Code+PKCE mit signiertem **Request Object (JAR)** als
Automatic-Registration-Nachweis, Token-Tausch mit `private_key_jwt`, ID-Token-Validierung gegen die
aus der Trust-Chain gewonnenen OP-JWKS, Claim-Mapping auf `FederatedIdentity`, plus Router
(`/openid/login`, `/openid/callback`, `/.well-known/openid-federation`), Settings und die `OidcRP`-Fassade.

**Architecture:** **Keine authlib** — eine schlanke, async-first RP-Schicht direkt auf der vorhandenen
`joserfc`-JOSE-Schicht und `httpx.AsyncClient`. OpenID Federation 1.0 §12.1.1 verlangt für Automatic
Registration einen **signierten Request Object** (JAR, `typ: oauth-authz-req+jwt`) oder PAR — v1 nutzt
JAR (`request=<JWT>`); PAR ist ein späterer Zusatz. Client-Auth am Token-Endpoint ist `private_key_jwt`
mit den RP-Federation-Keys, wobei der `aud` des Client-Assertions/Request-Objects laut Spec die
**OP-Entity-ID** ist (nicht die Token-Endpoint-URL). OP-Metadaten (Endpoints, Issuer, Protokoll-JWKS)
stammen ausschließlich aus `resolve_and_validate` (Plan 2), nicht aus klassischer OIDC-Discovery. Der
Session-Persistenz-Layer (Cookie/JWT + Store) kommt in Plan 4; Plan 3 endet an einer klaren Naht:
`OidcRP` ruft nach erfolgreichem Login einen einspeisbaren `on_authenticated(request, identity, next)`
-Callback (Default: Redirect auf `next`), den Plan 4 durch `SessionBackend.establish` ersetzt.

**Tech Stack:** Python 3.12+, joserfc 1.7+, httpx (async), FastAPI, Pydantic v2 + pydantic-settings,
pytest + pytest-asyncio, respx, ruff, ty, uv. Wiederverwendet Plan 1 (`identity.map_claims`,
`FederatedIdentity`, `select_identifier`) und Plan 2 (`federation.resolve_and_validate`,
`sign_rp_entity_configuration`, `jose`, `errors`).

## Global Constraints

- Distribution: `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header (`SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2`) in **jeder** Quellcodedatei unter `src/`.
- Python-Floor: `>=3.12`. async-first: HTTP über einen wiederverwendeten `httpx.AsyncClient`; keine blockierenden Netz-Calls.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung. Bei joserfc-TypedDict-vs-`dict`-Grenzen ist ein enger `cast(...)` erlaubt (wie in Plan 2 etabliert).
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren. `make lint` (scoped `src tests`) MUSS exit 0.
- **Sicherheits-Kern:** Algorithmen überall explizit gepinnt (`algorithms=[...]`, nie `none`). PKCE **S256** verpflichtend. `state` (CSRF) und `nonce` (ID-Token-Replay) sind pro Login zufällig, einmalig verwendbar und kurzlebig. ID-Token: Signatur gegen **OP-JWKS aus der Trust-Chain**, dann `iss`==OP-Issuer, `aud` enthält `client_id`, `azp`==`client_id` bei mehreren `aud`, `nonce` == gesendetem `nonce`, `exp`/`iat` mit Clock-Skew. `private_key_jwt`/Request-Object-`aud` == **OP-Entity-ID**. Open-Redirect-Guard für `next`. Keine Secrets/Token loggen.
- **Automatic Registration (§12.1.1):** `client_id` == RP-Entity-ID; kein `client_secret`; Schlüsselbesitz wird über den signierten Request Object nachgewiesen (JAR). Der Request Object hat `iss`==`client_id`==RP-Entity-ID, `aud`==OP-Entity-ID, **kein `sub`**, `jti`, `exp`, plus die Auth-Request-Parameter.
- Feld-Ausrichtung/Wiederverwendung: Claim-Mapping über das vorhandene `identity.map_claims` (Plan 1). `is_safe_redirect` wird **verbatim** aus dem SAML-Package gespiegelt.
- Niemals `git push`. Commits auf `main` sind für dieses greenfield-Repo ausdrücklich erlaubt.
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).

### Bewusst NICHT in Plan 3 (YAGNI / Folgepläne)

- **Session-Persistenz** (Cookie/JWT-Backend, Memory/Redis/Postgres-Store, `current_user`/`optional_user`): Plan 4. Plan 3 endet an der `on_authenticated`-Naht.
- **PAR** (Pushed Authorization Request, §12.1.1.2): späterer Zusatz; v1 nutzt JAR via `request=`.
- **Discovery/WAYF** (embedded OP-Auswahl): Plan 5. Plan 3 nimmt die OP-Entity-ID als Parameter/feste Einstellung.
- **RP-initiated Logout, `at_hash`/`c_hash`, `jwks_uri`-Fetch für OP-Keys, Explicit Registration, Trust Marks:** später. v1 erwartet eingebettete `jwks` in den aufgelösten OP-Metadaten.

## Verifizierte Fakten (Recherche — verbindlich)

- **Kein authlib.** authlib böte clientseitig **keinen** signierten Request Object / PAR (nur serverseitig) — genau das eine harte Stück müssten wir ohnehin selbst bauen. Sein `private_key_jwt`-Default-`aud` ist die Token-Endpoint-URL, was der Federation-Spec **widerspricht** (muss OP-Entity-ID sein). Die restliche authlib-Funktionalität (PKCE, URL-Bau, ID-Token-Claims) ist trivial bzw. bereits vorhanden. → schlanke eigene Schicht auf joserfc+httpx.
- **PKCE S256:** `code_challenge = BASE64URL-NO-PAD(SHA256(ASCII(code_verifier)))`. RFC-7636-Testvektor: verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
- **Request Object (§12.1.1.1):** signierter JWT, Header `typ: oauth-authz-req+jwt`, `alg`, `kid`; Claims: `iss`=RP-Entity-ID, `aud`=OP-Entity-ID (nur), `client_id`=RP-Entity-ID, **kein `sub`**, `jti`, `exp` (+`iat`), sowie `response_type=code`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`. In der Authorization-URL erscheinen zusätzlich `client_id`, `response_type`, `scope` und `request=<JWT>` als Query-Parameter.
- **Token-Endpoint (`private_key_jwt`):** POST `application/x-www-form-urlencoded` mit `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion=<JWT>`. Das Client-Assertion-JWT: `iss`=`sub`=`client_id`, `aud`=**OP-Entity-ID**, `jti`, `iat`, `exp`, signiert mit RP-Fed-Key.
- **ID-Token-Validierung:** identisches Muster wie `entity_statement.verify_statement` — `jose.verify_signature(id_token, op_keyset, algorithms=...)` (Signatur), dann explizite Claim-Checks. OP-JWKS = `resolve_and_validate(op).metadata["jwks"]` (eingebettet).
- **joserfc/httpx** wie in Plan 2 verifiziert (v1.7.4). `secrets.token_urlsafe` für `state`/`nonce`/`jti`/`code_verifier` (Laufzeitcode, kein Workflow-Skript — unkritisch).

## File Structure

```text
pyproject.toml                                        # (unverändert; Deps schon vorhanden)
src/fastapi_auth/openid/settings.py                   # OidcSettings (pydantic-settings)
src/fastapi_auth/openid/redirect.py                   # is_safe_redirect (gespiegelt vom SAML-Package)
src/fastapi_auth/openid/login_state.py                # LoginState + In-Memory-TTL-Store (transient auth state)
src/fastapi_auth/openid/oidc/__init__.py
src/fastapi_auth/openid/oidc/errors.py                # OIDC-Fehler (OidcError-Hierarchie)
src/fastapi_auth/openid/oidc/pkce.py                  # code_verifier / code_challenge (S256)
src/fastapi_auth/openid/oidc/request_object.py        # signierter Request Object (JAR)
src/fastapi_auth/openid/oidc/token.py                 # client_assertion + Token-Tausch + userinfo
src/fastapi_auth/openid/oidc/id_token.py              # ID-Token-Validierung
src/fastapi_auth/openid/oidc/login.py                 # begin_login / complete_login (Orchestrierung)
src/fastapi_auth/openid/router.py                     # FastAPI-Router (login/callback/well-known)
src/fastapi_auth/openid/rp.py                         # OidcRP-Fassade (Composition Root, mount, Naht)
tests/test_settings.py
tests/test_redirect.py
tests/oidc/__init__.py
tests/oidc/conftest.py                                # OP- + Federation-Testdouble (respx)
tests/oidc/test_pkce.py
tests/oidc/test_login_state.py
tests/oidc/test_request_object.py
tests/oidc/test_token.py
tests/oidc/test_id_token.py
tests/oidc/test_login_flow.py
tests/test_router.py
```

---

## Task 1: OidcSettings

**Files:**
- Create: `src/fastapi_auth/openid/settings.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: nichts.
- Produces: `OidcSettings(BaseSettings)` (env-prefix `OIDC_`) mit u. a.:
  - `entity_id: str`, `base_url: str`, `mount_path: str = "/openid"`, `redirect_path: str = "/openid/callback"`.
  - `fed_jwks: dict[str, object]` (RP-Federation-JWKS **inkl. privatem** Material), `authority_hints: list[str] = []`.
  - `trust_anchors: dict[str, dict[str, object]] = {}` (Entity-ID → öffentliche JWKS des Anchors).
  - `rp_metadata: dict[str, object] = {}` (zusätzliche `openid_relying_party`-Metadaten; `redirect_uris`/`client_name` werden ergänzt).
  - `scopes: list[str] = ["openid", "profile", "email"]`.
  - `id_token_signing_alg_values: list[str] = ["RS256", "ES256"]`.
  - `request_object_lifetime: int = 120`, `client_assertion_lifetime: int = 60`, `login_state_ttl: int = 300`, `clock_skew: int = 60`.
  - `fetch_userinfo: bool = False`.
  - `allowed_redirect_hosts: list[str] = []`.
  - Berechnet: `callback_url -> str` (`base_url` ohne trailing `/` + `redirect_path`), `absolute_url(path) -> str`, `well_known_path -> str` (`"/.well-known/openid-federation"`).
  - Validierung: `redirect_path` muss mit `mount_path` beginnen (sonst `ValueError`); `entity_id`/`base_url` sind Pflicht.

- [ ] **Step 1: Failing test schreiben**

`tests/test_settings.py`:

```python
"""Tests for OidcSettings configuration."""

from typing import Any, cast

import pytest
from pydantic import ValidationError

from fastapi_auth.openid.settings import OidcSettings

_JWKS: dict[str, Any] = {"keys": [{"kty": "RSA", "kid": "rp-1", "n": "x", "e": "AQAB"}]}
_BASE: dict[str, Any] = dict(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=_JWKS,
    authority_hints=["https://ta.example"],
    trust_anchors={"https://ta.example": {"keys": []}},
)


def test_defaults_and_derived_urls():
    s = OidcSettings(**_BASE)
    assert s.mount_path == "/openid"
    assert s.redirect_path == "/openid/callback"
    assert s.callback_url == "https://rp.example/openid/callback"
    assert s.absolute_url("/login") == "https://rp.example/openid/login"
    assert s.well_known_path == "/.well-known/openid-federation"
    assert s.scopes == ["openid", "profile", "email"]
    assert s.id_token_signing_alg_values == ["RS256", "ES256"]
    assert s.fetch_userinfo is False


def test_base_url_trailing_slash_stripped_in_callback():
    s = OidcSettings(**cast(dict[str, Any], {**_BASE, "base_url": "https://rp.example/"}))
    assert s.callback_url == "https://rp.example/openid/callback"


def test_missing_required_field_raises():
    incomplete = {k: v for k, v in _BASE.items() if k != "entity_id"}
    with pytest.raises(ValidationError):
        OidcSettings(**incomplete)


def test_redirect_path_must_be_under_mount_path():
    with pytest.raises(ValidationError, match="mount_path"):
        OidcSettings(**cast(dict[str, Any], {**_BASE, "redirect_path": "/elsewhere/callback"}))


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("OIDC_ENTITY_ID", "https://rp.example")
    monkeypatch.setenv("OIDC_BASE_URL", "https://rp.example")
    monkeypatch.setenv("OIDC_FED_JWKS", '{"keys": []}')
    s = OidcSettings()
    assert s.entity_id == "https://rp.example"
    assert s.fed_jwks == {"keys": []}


def test_lists_from_values():
    s = OidcSettings(**cast(dict[str, Any], {**_BASE, "scopes": ["openid"], "allowed_redirect_hosts": ["rp.example"]}))
    assert s.scopes == ["openid"]
    assert s.allowed_redirect_hosts == ["rp.example"]
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.openid.settings`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/settings.py`:

```python
"""Configuration for the OpenID Connect relying party (pydantic-settings).

Trust is established via OpenID Federation (Plan 2): ``trust_anchors`` are the
out-of-band-configured anchors a resolved chain must terminate at, and
``fed_jwks`` are this RP's federation keys (private material) used to sign the
entity configuration, request objects and client assertions.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WELL_KNOWN_PATH = "/.well-known/openid-federation"


class OidcSettings(BaseSettings):
    """Relying-party settings, populated from environment (prefix ``OIDC_``)."""

    model_config = SettingsConfigDict(env_prefix="OIDC_", env_file=".env", extra="ignore")

    # --- entity / endpoints ---
    entity_id: str
    base_url: str
    mount_path: str = "/openid"
    redirect_path: str = "/openid/callback"

    # --- federation keys / trust ---
    fed_jwks: dict[str, object]
    authority_hints: list[str] = Field(default_factory=list)
    trust_anchors: dict[str, dict[str, object]] = Field(default_factory=dict)
    rp_metadata: dict[str, object] = Field(default_factory=dict)

    # --- OIDC request ---
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    id_token_signing_alg_values: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    fetch_userinfo: bool = False

    # --- lifetimes / skew (seconds) ---
    request_object_lifetime: int = 120
    client_assertion_lifetime: int = 60
    login_state_ttl: int = 300
    clock_skew: int = 60

    # --- security ---
    allowed_redirect_hosts: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_redirect_under_mount(self) -> OidcSettings:
        if not self.redirect_path.startswith(self.mount_path):
            raise ValueError(
                f"redirect_path {self.redirect_path!r} must start with mount_path {self.mount_path!r}"
            )
        return self

    @property
    def _root(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def callback_url(self) -> str:
        """Absolute redirect_uri registered with / sent to the OP."""
        return self._root + self.redirect_path

    @property
    def well_known_path(self) -> str:
        """Path of this RP's entity configuration."""
        return _WELL_KNOWN_PATH

    def absolute_url(self, path: str) -> str:
        """Absolute URL for a router path relative to ``mount_path``."""
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{self._root}{self.mount_path}{suffix}"
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/settings.py tests/test_settings.py
git commit -m "feat(oidc): OidcSettings (Entity/Keys/Trust-Anchors/OIDC-Konfiguration)"
```

---

## Task 2: PKCE + Login-State-Store

**Files:**
- Create: `src/fastapi_auth/openid/oidc/__init__.py`, `src/fastapi_auth/openid/oidc/errors.py`, `src/fastapi_auth/openid/oidc/pkce.py`, `src/fastapi_auth/openid/login_state.py`
- Test: `tests/oidc/__init__.py`, `tests/oidc/test_pkce.py`, `tests/oidc/test_login_state.py`

**Interfaces:**
- Produces (`oidc.errors`): `OidcError(FederationError-Sibling? nein: eigene Basis)` — konkret: `OidcError(Exception)`, `AuthorizationError`, `TokenExchangeError`, `IdTokenError`, `LoginStateError`.
- Produces (`oidc.pkce`): `create_code_verifier() -> str`, `code_challenge_s256(verifier: str) -> str`.
- Produces (`login_state`):
  - `@dataclass(frozen=True) LoginState`: `state, nonce, code_verifier, op_entity_id, next_url` (alle `str`), `op_metadata: dict[str, object]`, `created: int`.
  - `LoginStateStore` (in-memory, TTL): `put(state: LoginState) -> None`, `pop(state_value: str, *, now: int | None = None) -> LoginState | None` (one-time-use, expired → None + evict), plus interne TTL aus dem Konstruktor.

- [ ] **Step 1: Failing tests schreiben**

`tests/oidc/__init__.py`: leere Datei.

`tests/oidc/test_pkce.py`:

```python
"""Tests for PKCE code verifier/challenge (RFC 7636)."""

from fastapi_auth.openid.oidc import pkce


def test_rfc7636_known_vector():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.code_challenge_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_verifier_length_and_charset():
    v = pkce.create_code_verifier()
    assert 43 <= len(v) <= 128
    assert all(c.isalnum() or c in "-._~" for c in v)


def test_challenge_has_no_padding():
    assert "=" not in pkce.code_challenge_s256(pkce.create_code_verifier())
```

`tests/oidc/test_login_state.py`:

```python
"""Tests for the transient login-state store."""

from fastapi_auth.openid.login_state import LoginState, LoginStateStore

NOW = 1_700_000_000


def _state(value: str = "s1") -> LoginState:
    return LoginState(
        state=value,
        nonce="n1",
        code_verifier="v1",
        op_entity_id="https://op.example",
        next_url="/app",
        op_metadata={"issuer": "https://op.example"},
        created=NOW,
    )


def test_put_then_pop_returns_state_once():
    store = LoginStateStore(ttl=300)
    store.put(_state("abc"))
    got = store.pop("abc", now=NOW + 10)
    assert got is not None
    assert got.nonce == "n1"
    # one-time use: second pop is None
    assert store.pop("abc", now=NOW + 10) is None


def test_pop_unknown_returns_none():
    assert LoginStateStore(ttl=300).pop("nope", now=NOW) is None


def test_expired_state_is_evicted():
    store = LoginStateStore(ttl=300)
    store.put(_state("old"))
    assert store.pop("old", now=NOW + 1000) is None
```

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/oidc/test_pkce.py tests/oidc/test_login_state.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/oidc/__init__.py`:

```python
"""OIDC relying-party client layer (PKCE, request object, token, id_token).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/openid/oidc/errors.py`:

```python
"""Exception hierarchy for the OIDC relying-party layer.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class OidcError(Exception):
    """Base class for all OIDC relying-party failures."""


class AuthorizationError(OidcError):
    """The authorization request could not be built or the callback is malformed."""


class TokenExchangeError(OidcError):
    """The token endpoint returned an error or an unusable response."""


class IdTokenError(OidcError):
    """The ID token failed signature or claim validation."""


class LoginStateError(OidcError):
    """The login state is unknown, expired, or already used (possible CSRF)."""
```

`src/fastapi_auth/openid/oidc/pkce.py`:

```python
"""PKCE code verifier and S256 challenge (RFC 7636).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def create_code_verifier() -> str:
    """Return a high-entropy code verifier (unreserved chars, 43-128 length)."""
    return secrets.token_urlsafe(64)


def code_challenge_s256(verifier: str) -> str:
    """Return BASE64URL(SHA256(verifier)) without padding (``S256`` method)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
```

`src/fastapi_auth/openid/login_state.py`:

```python
"""Transient login-state store: correlates an OIDC callback with its request.

Holds the short-lived ``state``/``nonce``/``code_verifier`` (and the resolved
OP metadata) between ``/login`` and ``/callback``. State is single-use and
expires after ``ttl`` seconds. This is NOT the user session (that is Plan 4);
it is the OIDC equivalent of the SAML in-flight AuthnRequest cache.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class LoginState:
    """Correlated state for one in-flight authorization-code login."""

    state: str
    nonce: str
    code_verifier: str
    op_entity_id: str
    next_url: str
    op_metadata: dict[str, object]
    created: int


class LoginStateStore:
    """In-memory, single-use, TTL-bounded store keyed by ``state``."""

    def __init__(self, ttl: int = 300) -> None:
        """Create a store whose entries expire ``ttl`` seconds after creation."""
        self._ttl = ttl
        self._entries: dict[str, LoginState] = {}

    def put(self, state: LoginState) -> None:
        """Store a login state under its ``state`` value."""
        self._entries[state.state] = state

    def pop(self, state_value: str, *, now: int | None = None) -> LoginState | None:
        """Remove and return the state; None if unknown, expired, or already used."""
        moment = int(time.time()) if now is None else now
        entry = self._entries.pop(state_value, None)
        if entry is None:
            return None
        if entry.created + self._ttl <= moment:
            return None
        return entry
```

- [ ] **Step 4: Tests grün laufen lassen**

Run: `uv run pytest tests/oidc/test_pkce.py tests/oidc/test_login_state.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/oidc/__init__.py src/fastapi_auth/openid/oidc/errors.py src/fastapi_auth/openid/oidc/pkce.py src/fastapi_auth/openid/login_state.py tests/oidc/__init__.py tests/oidc/test_pkce.py tests/oidc/test_login_state.py
git commit -m "feat(oidc): PKCE (S256) + transienter Login-State-Store + Fehlerhierarchie"
```

---

## Task 3: Request Object (JAR)

**Files:**
- Create: `src/fastapi_auth/openid/oidc/request_object.py`
- Test: `tests/oidc/test_request_object.py`

**Interfaces:**
- Consumes: `federation.jose` (`sign` via `jwt.encode`-Muster), joserfc.
- Produces:
  - `REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"`
  - `build_request_object(*, client_id, op_entity_id, redirect_uri, scope, state, nonce, code_challenge, response_type="code", lifetime=120, now=None, jti=None) -> dict` — Claims: `iss=client_id`, `aud=op_entity_id`, **kein `sub`**, `jti`, `iat`, `exp`, `client_id`, `response_type`, `redirect_uri`, `scope` (space-joined String), `state`, `nonce`, `code_challenge`, `code_challenge_method="S256"`.
  - `sign_request_object(claims: dict, key, *, trust_chain: list[str] | None = None) -> str` — signiert mit `typ: oauth-authz-req+jwt`; wenn `trust_chain` gegeben, als JWS-Header-Parameter `trust_chain` beilegen.

- [ ] **Step 1: Failing test schreiben**

`tests/oidc/test_request_object.py`:

```python
"""Tests for the signed authorization request object (JAR, federation §12.1.1.1)."""

from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import request_object as ro

NOW = 1_700_000_000


def _key(kid: str = "rp-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_request_object_claims_shape():
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid", "profile"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    assert claims["iss"] == "https://rp.example"
    assert claims["client_id"] == "https://rp.example"
    assert claims["aud"] == "https://op.example"  # OP entity id only
    assert "sub" not in claims  # MUST NOT be present
    assert claims["response_type"] == "code"
    assert claims["scope"] == "openid profile"  # space-joined
    assert claims["code_challenge"] == "cc"
    assert claims["code_challenge_method"] == "S256"
    assert claims["state"] == "st"
    assert claims["nonce"] == "no"
    assert claims["exp"] == NOW + 120
    assert claims["jti"] == "j1"


def test_sign_request_object_typ_header_and_verifies():
    key = _key("rp-1")
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    token = ro.sign_request_object(claims, key)
    assert jose.peek_header(token)["typ"] == ro.REQUEST_OBJECT_TYP
    verified = jose.verify_signature(token, KeySet([key]), algorithms=["RS256"])
    assert verified["aud"] == "https://op.example"


def test_sign_request_object_includes_trust_chain_header():
    key = _key("rp-1")
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    token = ro.sign_request_object(claims, key, trust_chain=["ec.jwt", "sub.jwt"])
    assert jose.peek_header(token)["trust_chain"] == ["ec.jwt", "sub.jwt"]
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/oidc/test_request_object.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/oidc/request_object.py`:

```python
"""Signed authorization request object (JAR) for automatic registration.

OpenID Federation 1.0 §12.1.1.1 requires the authorization request to prove
control of the RP's federation keys via a signed request object typed
``oauth-authz-req+jwt``. Its ``aud`` is the OP's Entity Identifier only, its
``iss``/``client_id`` are the RP's Entity Identifier, and it MUST NOT carry a
``sub`` claim (which would let it be replayed as a private_key_jwt assertion).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

from joserfc import jwt
from joserfc.jwk import Key

from fastapi_auth.openid.federation import jose

REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"


def build_request_object(
    *,
    client_id: str,
    op_entity_id: str,
    redirect_uri: str,
    scope: Sequence[str],
    state: str,
    nonce: str,
    code_challenge: str,
    response_type: str = "code",
    lifetime: int = 120,
    now: int | None = None,
    jti: str | None = None,
) -> dict[str, object]:
    """Build the request-object claims (no ``sub``; ``aud`` = OP entity id)."""
    issued = jose.now_epoch() if now is None else now
    return {
        "iss": client_id,
        "aud": op_entity_id,
        "client_id": client_id,
        "jti": jti if jti is not None else secrets.token_urlsafe(16),
        "iat": issued,
        "exp": issued + lifetime,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scope),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }


def sign_request_object(
    claims: dict[str, object],
    key: Key,
    *,
    trust_chain: list[str] | None = None,
) -> str:
    """Sign a request object as an ``oauth-authz-req+jwt`` compact JWS."""
    alg = jose.signing_alg(key)
    header: dict[str, object] = {"alg": alg, "typ": REQUEST_OBJECT_TYP, "kid": key.kid}
    if trust_chain is not None:
        header["trust_chain"] = trust_chain
    return jwt.encode(header, claims, key, algorithms=[alg])
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/oidc/test_request_object.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/oidc/request_object.py tests/oidc/test_request_object.py
git commit -m "feat(oidc): signierter Request Object (JAR) fuer Automatic Registration"
```

---

## Task 4: Client-Assertion + Token-Tausch + userinfo

**Files:**
- Create: `src/fastapi_auth/openid/oidc/token.py`
- Test: `tests/oidc/test_token.py`

**Interfaces:**
- Consumes: `federation.jose`, `oidc.errors.TokenExchangeError`, httpx.
- Produces:
  - `CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
  - `build_client_assertion(*, client_id, op_entity_id, lifetime=60, now=None, jti=None) -> dict` — `iss=sub=client_id`, `aud=op_entity_id`, `jti`, `iat`, `exp`.
  - `sign_client_assertion(claims: dict, key) -> str`.
  - `async exchange_code(client, *, token_endpoint, code, redirect_uri, code_verifier, client_id, client_assertion) -> dict` — POST form-encoded; bei HTTP-Fehler/`error`-Body → `TokenExchangeError`; sonst das Token-JSON (`dict`), das mind. `id_token` enthalten muss (sonst `TokenExchangeError`).
  - `async fetch_userinfo(client, *, userinfo_endpoint, access_token) -> dict` — GET mit Bearer; JSON → `dict`; Fehler → `TokenExchangeError`.

- [ ] **Step 1: Failing test schreiben**

`tests/oidc/test_token.py`:

```python
"""Tests for client-assertion signing, token exchange and userinfo."""

import httpx
import pytest
import respx
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import token
from fastapi_auth.openid.oidc.errors import TokenExchangeError

NOW = 1_700_000_000


def _key(kid: str = "rp-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_client_assertion_aud_is_op_entity_id():
    claims = token.build_client_assertion(
        client_id="https://rp.example", op_entity_id="https://op.example", now=NOW, jti="j1"
    )
    assert claims["iss"] == claims["sub"] == "https://rp.example"
    assert claims["aud"] == "https://op.example"  # NOT the token endpoint URL
    assert claims["exp"] == NOW + 60


def test_sign_client_assertion_verifies():
    key = _key()
    ca = token.sign_client_assertion(
        token.build_client_assertion(
            client_id="https://rp.example", op_entity_id="https://op.example", now=NOW, jti="j1"
        ),
        key,
    )
    assert jose.verify_signature(ca, KeySet([key]), algorithms=["RS256"])["aud"] == "https://op.example"


@pytest.mark.asyncio
async def test_exchange_code_posts_expected_form_and_returns_tokens():
    with respx.mock:
        route = respx.post("https://op.example/token").respond(
            200, json={"access_token": "at", "id_token": "idt", "token_type": "Bearer"}
        )
        async with httpx.AsyncClient() as client:
            tokens = await token.exchange_code(
                client,
                token_endpoint="https://op.example/token",
                code="c",
                redirect_uri="https://rp.example/openid/callback",
                code_verifier="v",
                client_id="https://rp.example",
                client_assertion="ca.jwt",
            )
    assert tokens["id_token"] == "idt"
    form = dict(httpx.QueryParams(route.calls.last.request.content.decode()))
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "c"
    assert form["code_verifier"] == "v"
    assert form["client_id"] == "https://rp.example"
    assert form["client_assertion"] == "ca.jwt"
    assert form["client_assertion_type"] == token.CLIENT_ASSERTION_TYPE


@pytest.mark.asyncio
async def test_exchange_code_error_body_raises():
    with respx.mock:
        respx.post("https://op.example/token").respond(400, json={"error": "invalid_grant"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(TokenExchangeError, match="invalid_grant"):
                await token.exchange_code(
                    client,
                    token_endpoint="https://op.example/token",
                    code="c",
                    redirect_uri="https://rp.example/openid/callback",
                    code_verifier="v",
                    client_id="https://rp.example",
                    client_assertion="ca.jwt",
                )


@pytest.mark.asyncio
async def test_exchange_code_missing_id_token_raises():
    with respx.mock:
        respx.post("https://op.example/token").respond(200, json={"access_token": "at"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(TokenExchangeError, match="id_token"):
                await token.exchange_code(
                    client,
                    token_endpoint="https://op.example/token",
                    code="c",
                    redirect_uri="https://rp.example/openid/callback",
                    code_verifier="v",
                    client_id="https://rp.example",
                    client_assertion="ca.jwt",
                )


@pytest.mark.asyncio
async def test_fetch_userinfo_sends_bearer():
    with respx.mock:
        route = respx.get("https://op.example/userinfo").respond(200, json={"sub": "u", "email": "u@x"})
        async with httpx.AsyncClient() as client:
            claims = await token.fetch_userinfo(
                client, userinfo_endpoint="https://op.example/userinfo", access_token="at"
            )
    assert claims["email"] == "u@x"
    assert route.calls.last.request.headers["authorization"] == "Bearer at"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/oidc/test_token.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/oidc/token.py`:

```python
"""Client assertion (private_key_jwt), token exchange and userinfo.

Client authentication at the token endpoint is ``private_key_jwt`` signed with
the RP's federation key. Per OpenID Federation 1.0 §12.1.1.2 the assertion's
``aud`` MUST be the OP's Entity Identifier — not the token endpoint URL, which
is the plain OIDC default. The token endpoint URL is only the POST target.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

import httpx
from joserfc import jwt
from joserfc.jwk import Key

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc.errors import TokenExchangeError

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def build_client_assertion(
    *,
    client_id: str,
    op_entity_id: str,
    lifetime: int = 60,
    now: int | None = None,
    jti: str | None = None,
) -> dict[str, object]:
    """Build the private_key_jwt client-assertion claims (``aud`` = OP entity id)."""
    issued = jose.now_epoch() if now is None else now
    return {
        "iss": client_id,
        "sub": client_id,
        "aud": op_entity_id,
        "jti": jti if jti is not None else secrets.token_urlsafe(16),
        "iat": issued,
        "exp": issued + lifetime,
    }


def sign_client_assertion(claims: dict[str, object], key: Key) -> str:
    """Sign the client-assertion claims as a compact JWS."""
    alg = jose.signing_alg(key)
    header = {"alg": alg, "typ": "JWT", "kid": key.kid}
    return jwt.encode(header, claims, key, algorithms=[alg])


async def exchange_code(
    client: httpx.AsyncClient,
    *,
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_id: str,
    client_assertion: str,
) -> dict[str, object]:
    """Exchange an authorization code for tokens using private_key_jwt auth."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": client_assertion,
    }
    try:
        response = await client.post(token_endpoint, data=data)
    except httpx.HTTPError as exc:
        raise TokenExchangeError(f"token request to {token_endpoint} failed: {exc}") from exc
    if response.status_code >= 400:
        raise TokenExchangeError(_describe_error(response))
    tokens = response.json()
    if not isinstance(tokens, dict) or "id_token" not in tokens:
        raise TokenExchangeError("token response is missing id_token")
    return tokens


async def fetch_userinfo(
    client: httpx.AsyncClient,
    *,
    userinfo_endpoint: str,
    access_token: str,
) -> dict[str, object]:
    """Fetch userinfo claims with the access token as a bearer credential."""
    try:
        response = await client.get(
            userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise TokenExchangeError(f"userinfo request failed: {exc}") from exc
    claims = response.json()
    if not isinstance(claims, dict):
        raise TokenExchangeError("userinfo response is not a JSON object")
    return claims


def _describe_error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"token endpoint returned HTTP {response.status_code}"
    if isinstance(body, dict) and "error" in body:
        description = body.get("error_description", "")
        return f"token endpoint error: {body['error']} {description}".strip()
    return f"token endpoint returned HTTP {response.status_code}"
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/oidc/test_token.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/oidc/token.py tests/oidc/test_token.py
git commit -m "feat(oidc): private_key_jwt Client-Assertion + Token-Tausch + userinfo"
```

---

## Task 5: ID-Token-Validierung (adversarial)

**Files:**
- Create: `src/fastapi_auth/openid/oidc/id_token.py`
- Test: `tests/oidc/test_id_token.py`

**Interfaces:**
- Consumes: `federation.jose.verify_signature`, `oidc.errors.IdTokenError`, joserfc.
- Produces:
  - `validate_id_token(id_token: str, *, op_jwks: dict[str, object], issuer: str, client_id: str, nonce: str, algorithms: Sequence[str], leeway: int = 60, now: int | None = None) -> dict` — Signatur gegen `op_jwks` (KeySet); dann: `iss == issuer`; `aud` enthält `client_id` (String oder Liste); bei mehreren `aud` MUSS `azp == client_id`; `nonce == nonce`; `exp`/`iat` mit `leeway`. Fehler → `IdTokenError` mit sprechender Meldung.

- [ ] **Step 1: Failing test schreiben**

`tests/oidc/test_id_token.py`:

```python
"""Adversarial tests for ID-token validation."""

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import id_token as idt
from fastapi_auth.openid.oidc.errors import IdTokenError

NOW = 1_700_000_000
ISS = "https://op.example"
CID = "https://rp.example"


def _op_key(kid: str = "op-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def _sign(key: RSAKey, claims: dict) -> str:
    return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key, algorithms=["RS256"])


def _claims(**over) -> dict:
    base = {"iss": ISS, "sub": "u1", "aud": CID, "nonce": "n1", "iat": NOW, "exp": NOW + 300}
    base.update(over)
    return base


def _jwks(key: RSAKey) -> dict:
    return jose.public_jwks(KeySet([key]))


def test_valid_id_token_passes():
    key = _op_key()
    token = _sign(key, _claims())
    claims = idt.validate_id_token(
        token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10
    )
    assert claims["sub"] == "u1"


def test_wrong_nonce_rejected():
    key = _op_key()
    token = _sign(key, _claims(nonce="attacker"))
    with pytest.raises(IdTokenError, match="nonce"):
        idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)


def test_wrong_issuer_rejected():
    key = _op_key()
    token = _sign(key, _claims(iss="https://evil.example"))
    with pytest.raises(IdTokenError, match="iss"):
        idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)


def test_aud_without_client_id_rejected():
    key = _op_key()
    token = _sign(key, _claims(aud="https://other.example"))
    with pytest.raises(IdTokenError, match="aud"):
        idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)


def test_multi_aud_requires_matching_azp():
    key = _op_key()
    token = _sign(key, _claims(aud=[CID, "https://other.example"]))  # no azp
    with pytest.raises(IdTokenError, match="azp"):
        idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)


def test_multi_aud_with_correct_azp_passes():
    key = _op_key()
    token = _sign(key, _claims(aud=[CID, "https://other.example"], azp=CID))
    claims = idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)
    assert claims["azp"] == CID


def test_bad_signature_rejected():
    token = _sign(_op_key("real"), _claims())
    with pytest.raises(Exception):  # SignatureError from jose bubbles as failure
        idt.validate_id_token(token, op_jwks=_jwks(_op_key("attacker")), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 10)


def test_expired_rejected():
    key = _op_key()
    token = _sign(key, _claims(exp=NOW - 10))
    with pytest.raises(IdTokenError, match="expired"):
        idt.validate_id_token(token, op_jwks=_jwks(key), issuer=ISS, client_id=CID, nonce="n1", algorithms=["RS256"], now=NOW + 100)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/oidc/test_id_token.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/oidc/id_token.py`:

```python
"""ID-token validation against OP keys obtained from the federation trust chain.

Mirrors ``federation.entity_statement.verify_statement``: verify the JWS
signature with the OP's protocol JWKS (resolved via the trust chain), then run
explicit OIDC claim checks (iss, aud/azp, nonce, exp/iat). The signature keys
are the ones the trust chain validated — never fetched from unauthenticated
discovery.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import SignatureError
from fastapi_auth.openid.oidc.errors import IdTokenError


def validate_id_token(
    id_token: str,
    *,
    op_jwks: dict[str, object],
    issuer: str,
    client_id: str,
    nonce: str,
    algorithms: Sequence[str],
    leeway: int = 60,
    now: int | None = None,
) -> dict[str, object]:
    """Verify the ID token's signature and validate its claims."""
    keyset = jose.load_keyset(op_jwks)
    try:
        claims = jose.verify_signature(id_token, keyset, algorithms=algorithms)
    except SignatureError as exc:
        raise IdTokenError(f"id_token signature invalid: {exc}") from exc

    if claims.get("iss") != issuer:
        raise IdTokenError(f"id_token iss {claims.get('iss')!r} != expected {issuer!r}")

    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in audiences:
        raise IdTokenError(f"id_token aud does not include client_id {client_id!r}")
    if len(audiences) > 1 and claims.get("azp") != client_id:
        raise IdTokenError("id_token has multiple aud but azp != client_id")

    if claims.get("nonce") != nonce:
        raise IdTokenError("id_token nonce does not match the login request")

    moment = jose.now_epoch() if now is None else now
    exp = claims.get("exp")
    iat = claims.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        raise IdTokenError("id_token has non-integer iat/exp")
    if exp < moment - leeway:
        raise IdTokenError("id_token is expired")
    if iat > moment + leeway:
        raise IdTokenError("id_token iat is in the future")

    return claims
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/oidc/test_id_token.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/oidc/id_token.py tests/oidc/test_id_token.py
git commit -m "feat(oidc): ID-Token-Validierung (Signatur gegen Trust-Chain-JWKS + Claims)"
```

---

## Task 6: Login-Orchestrierung + OP-/Federation-Testdouble

**Files:**
- Create: `src/fastapi_auth/openid/oidc/login.py`
- Create: `tests/oidc/conftest.py` (OP + Federation Testdouble — von Task 7/8 wiederverwendet)
- Test: `tests/oidc/test_login_flow.py`

**Interfaces:**
- Consumes: `federation.resolve_and_validate`, `federation.jose`, `oidc.pkce`, `oidc.request_object`, `oidc.token`, `oidc.id_token`, `login_state`, `identity.map_claims`.
- Produces:
  - `@dataclass(frozen=True) AuthorizationRedirect`: `url: str`, `state: str`.
  - `async begin_login(*, http_client, settings, fed_signing_key, op_entity_id, next_url, state_store, now=None) -> AuthorizationRedirect` — `resolve_and_validate(op)` → PKCE → Request Object → `state`/`nonce` erzeugen, `LoginState` (inkl. aufgelöster OP-Metadaten) speichern → Authorization-URL bauen (`authorization_endpoint?client_id&response_type=code&scope&request=<JWT>`).
  - `async complete_login(*, http_client, settings, fed_signing_key, login_state, code, now=None) -> FederatedIdentity` — Token-Tausch (client_assertion, `aud`=OP-Entity-ID), ID-Token-Validierung gegen `login_state.op_metadata["jwks"]`, optional userinfo, Claims mergen → `map_claims`.
  - Hilfsfunktion `_authorization_url(endpoint, *, client_id, scope, request_jwt) -> str`.

- [ ] **Step 1: Failing test + Testdouble schreiben**

`tests/oidc/conftest.py`:

```python
"""OP + federation test double for OIDC login flow tests.

Builds an in-memory federation (trust anchor -> OP leaf) whose OP entity
publishes ``openid_provider`` metadata (endpoints + protocol jwks) and mocks the
``.well-known``/fetch endpoints plus the OP token/userinfo endpoints via respx.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import fetch, jose

NOW = 1_700_000_000
RP_ENTITY = "https://rp.example"
OP_ENTITY = "https://op.example"
TA_ENTITY = "https://ta.example"


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


@dataclass
class OpFixture:
    """A federated OP with federation keys, protocol keys and signed statements."""

    fed_key: RSAKey = field(default_factory=lambda: _key("op-fed"))
    protocol_key: RSAKey = field(default_factory=lambda: _key("op-proto"))
    ta_key: RSAKey = field(default_factory=lambda: _key("ta-fed"))
    rp_fed_key: RSAKey = field(default_factory=lambda: _key("rp-fed"))
    now: int = NOW

    def op_metadata(self) -> dict[str, object]:
        return {
            "openid_provider": {
                "issuer": OP_ENTITY,
                "authorization_endpoint": f"{OP_ENTITY}/authorize",
                "token_endpoint": f"{OP_ENTITY}/token",
                "userinfo_endpoint": f"{OP_ENTITY}/userinfo",
                "jwks": jose.public_jwks(KeySet([self.protocol_key])),
            }
        }

    def op_entity_configuration(self) -> str:
        claims = es.build_entity_configuration(
            entity_id=OP_ENTITY,
            jwks=jose.public_jwks(KeySet([self.fed_key])),
            authority_hints=[TA_ENTITY],
            metadata=self.op_metadata(),
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.fed_key)

    def ta_entity_configuration(self) -> str:
        claims = es.build_entity_configuration(
            entity_id=TA_ENTITY,
            jwks=jose.public_jwks(KeySet([self.ta_key])),
            metadata={"federation_entity": {"federation_fetch_endpoint": f"{TA_ENTITY}/fetch"}},
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.ta_key)

    def subordinate_about_op(self) -> str:
        claims = es.build_subordinate_statement(
            issuer=TA_ENTITY,
            subject=OP_ENTITY,
            jwks=jose.public_jwks(KeySet([self.fed_key])),
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.ta_key)

    def trust_anchors(self) -> dict[str, dict[str, object]]:
        return {TA_ENTITY: jose.public_jwks(KeySet([self.ta_key]))}

    def id_token(self, *, nonce: str, sub: str = "u1", **over: object) -> str:
        claims: dict[str, object] = {
            "iss": OP_ENTITY,
            "sub": sub,
            "aud": RP_ENTITY,
            "nonce": nonce,
            "iat": self.now,
            "exp": self.now + 300,
            "email": "u@lmu.de",
            "eduperson_principal_name": f"{sub}@lmu.de",
        }
        claims.update(over)
        return jwt.encode(
            {"alg": "RS256", "kid": self.protocol_key.kid}, claims, self.protocol_key, algorithms=["RS256"]
        )

    def mount(self, router: respx.Router) -> None:
        router.get(fetch.well_known_url(OP_ENTITY)).respond(
            200, text=self.op_entity_configuration(), headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )
        router.get(fetch.well_known_url(TA_ENTITY)).respond(
            200, text=self.ta_entity_configuration(), headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )
        router.get(f"{TA_ENTITY}/fetch").respond(
            200, text=self.subordinate_about_op(), headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )


@pytest.fixture
def op() -> OpFixture:
    return OpFixture()


@pytest.fixture
def mock_router() -> respx.Router:
    return respx.mock(assert_all_called=False)
```

`tests/oidc/test_login_flow.py`:

```python
"""End-to-end tests for begin_login / complete_login over the OP+federation double."""

import httpx
import pytest
from urllib.parse import parse_qs, urlparse

from fastapi_auth.openid import login_state as ls
from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import login, request_object
from fastapi_auth.openid.settings import OidcSettings
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY


def _settings(op) -> OidcSettings:
    return OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=jose.public_jwks(_ks(op.rp_fed_key)),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        scopes=["openid", "profile", "email"],
    )


def _ks(key):
    from joserfc.jwk import KeySet

    return KeySet([key])


@pytest.mark.asyncio
async def test_begin_login_builds_authorization_redirect(op, mock_router):
    op.mount(mock_router)
    store = ls.LoginStateStore(ttl=300)
    with mock_router:
        async with httpx.AsyncClient() as client:
            redirect = await login.begin_login(
                http_client=client,
                settings=_settings(op),
                fed_signing_key=op.rp_fed_key,
                op_entity_id=OP_ENTITY,
                next_url="/app",
                state_store=store,
                now=NOW + 10,
            )
    parsed = urlparse(redirect.url)
    assert parsed.path == "/authorize"
    q = parse_qs(parsed.query)
    assert q["client_id"] == [RP_ENTITY]
    assert q["response_type"] == ["code"]
    assert "request" in q  # signed request object present
    ro_header = jose.peek_header(q["request"][0])
    assert ro_header["typ"] == request_object.REQUEST_OBJECT_TYP
    # login state stored under the returned state value
    popped = store.pop(redirect.state, now=NOW + 20)
    assert popped is not None
    assert popped.op_entity_id == OP_ENTITY


@pytest.mark.asyncio
async def test_complete_login_returns_identity(op, mock_router):
    op.mount(mock_router)
    store = ls.LoginStateStore(ttl=300)
    settings = _settings(op)
    with mock_router:
        async with httpx.AsyncClient() as client:
            redirect = await login.begin_login(
                http_client=client, settings=settings, fed_signing_key=op.rp_fed_key,
                op_entity_id=OP_ENTITY, next_url="/app", state_store=store, now=NOW + 10,
            )
            state = store.pop(redirect.state, now=NOW + 20)  # emulate router pop
            # OP token endpoint returns an id_token bound to the login nonce.
            mock_router.post(f"{OP_ENTITY}/token").respond(
                200, json={"access_token": "at", "id_token": op.id_token(nonce=state.nonce), "token_type": "Bearer"}
            )
            identity = await login.complete_login(
                http_client=client, settings=settings, fed_signing_key=op.rp_fed_key,
                login_state=state, code="the-code", now=NOW + 30,
            )
    assert identity.sub == "u1"
    assert identity.mail == ["u@lmu.de"]
    assert identity.eppn == "u1@lmu.de"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/oidc/test_login_flow.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.openid.oidc.login`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/oidc/login.py`:

```python
"""Login orchestration: begin_login (authorization redirect) and complete_login.

Ties the federation trust layer (Plan 2) to the OIDC client pieces: resolve and
validate the OP's metadata, build a PKCE + signed request object authorization
redirect, then on callback exchange the code (private_key_jwt) and validate the
id_token against the OP keys the trust chain produced, mapping claims to a
``FederatedIdentity``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.trust_chain import resolve_and_validate
from fastapi_auth.openid.identity.mapper import map_claims
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.login_state import LoginState, LoginStateStore
from fastapi_auth.openid.oidc import id_token as idt
from fastapi_auth.openid.oidc import pkce, request_object, token
from fastapi_auth.openid.oidc.errors import AuthorizationError
from fastapi_auth.openid.settings import OidcSettings


@dataclass(frozen=True)
class AuthorizationRedirect:
    """The OP authorization URL to redirect the browser to, plus its state."""

    url: str
    state: str


def _authorization_url(endpoint: str, *, client_id: str, scope: list[str], request_jwt: str) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(scope),
            "request": request_jwt,
        }
    )
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{query}"


def _op_provider_metadata(metadata: dict[str, object]) -> dict[str, object]:
    provider = metadata
    if not isinstance(provider, dict) or "issuer" not in provider:
        raise AuthorizationError("resolved OP metadata is missing issuer/endpoints")
    return provider


async def begin_login(
    *,
    http_client: httpx.AsyncClient,
    settings: OidcSettings,
    fed_signing_key: object,
    op_entity_id: str,
    next_url: str,
    state_store: LoginStateStore,
    now: int | None = None,
) -> AuthorizationRedirect:
    """Resolve the OP, build the PKCE + request-object redirect, store login state."""
    resolved = await resolve_and_validate(
        http_client,
        op_entity_id,
        settings.trust_anchors,
        entity_type="openid_provider",
        leeway=settings.clock_skew,
        now=now,
    )
    provider = _op_provider_metadata(resolved.metadata)
    authorization_endpoint = provider.get("authorization_endpoint")
    if not isinstance(authorization_endpoint, str):
        raise AuthorizationError("resolved OP metadata is missing authorization_endpoint")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = pkce.create_code_verifier()
    challenge = pkce.code_challenge_s256(verifier)

    claims = request_object.build_request_object(
        client_id=settings.entity_id,
        op_entity_id=op_entity_id,
        redirect_uri=settings.callback_url,
        scope=settings.scopes,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
        lifetime=settings.request_object_lifetime,
        now=now,
    )
    request_jwt = request_object.sign_request_object(claims, fed_signing_key)  # type: ignore[arg-type]

    state_store.put(
        LoginState(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            op_entity_id=op_entity_id,
            next_url=next_url,
            op_metadata=provider,
            created=jose.now_epoch() if now is None else now,
        )
    )
    url = _authorization_url(
        authorization_endpoint, client_id=settings.entity_id, scope=settings.scopes, request_jwt=request_jwt
    )
    return AuthorizationRedirect(url=url, state=state)


async def complete_login(
    *,
    http_client: httpx.AsyncClient,
    settings: OidcSettings,
    fed_signing_key: object,
    login_state: LoginState,
    code: str,
    now: int | None = None,
) -> FederatedIdentity:
    """Exchange the code, validate the id_token, and map claims to an identity."""
    provider = login_state.op_metadata
    token_endpoint = provider.get("token_endpoint")
    op_jwks = provider.get("jwks")
    issuer = provider.get("issuer")
    if not (isinstance(token_endpoint, str) and isinstance(op_jwks, dict) and isinstance(issuer, str)):
        raise AuthorizationError("stored OP metadata is incomplete")

    assertion = token.sign_client_assertion(
        token.build_client_assertion(
            client_id=settings.entity_id,
            op_entity_id=login_state.op_entity_id,
            lifetime=settings.client_assertion_lifetime,
            now=now,
        ),
        fed_signing_key,  # type: ignore[arg-type]
    )
    tokens = await token.exchange_code(
        http_client,
        token_endpoint=token_endpoint,
        code=code,
        redirect_uri=settings.callback_url,
        code_verifier=login_state.code_verifier,
        client_id=settings.entity_id,
        client_assertion=assertion,
    )

    id_claims = idt.validate_id_token(
        str(tokens["id_token"]),
        op_jwks=op_jwks,
        issuer=issuer,
        client_id=settings.entity_id,
        nonce=login_state.nonce,
        algorithms=settings.id_token_signing_alg_values,
        leeway=settings.clock_skew,
        now=now,
    )

    claims: dict[str, object] = dict(id_claims)
    if settings.fetch_userinfo:
        userinfo_endpoint = provider.get("userinfo_endpoint")
        access_token = tokens.get("access_token")
        if isinstance(userinfo_endpoint, str) and isinstance(access_token, str):
            userinfo = await token.fetch_userinfo(
                http_client, userinfo_endpoint=userinfo_endpoint, access_token=access_token
            )
            claims.update(userinfo)

    return map_claims(claims)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/oidc/test_login_flow.py -v`
Expected: alle passed. (Falls `resolve_and_validate` scheitert: prüfe, dass die conftest-`OpFixture` `authority_hints`/`federation_fetch_endpoint` korrekt setzt und das Subordinate Statement mit dem TA-Key signiert ist.)

- [ ] **Step 5: Lint + Teil-Suite**

Run: `uv run pytest tests/oidc -q && make lint`
Expected: grün; exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/oidc/login.py tests/oidc/conftest.py tests/oidc/test_login_flow.py
git commit -m "feat(oidc): Login-Orchestrierung (begin/complete) + OP-Federation-Testdouble"
```

---

## Task 7: Router + OidcRP-Fassade + Redirect-Guard

**Files:**
- Create: `src/fastapi_auth/openid/redirect.py`, `src/fastapi_auth/openid/router.py`, `src/fastapi_auth/openid/rp.py`
- Test: `tests/test_redirect.py`, `tests/test_router.py`

**Interfaces:**
- Consumes: `settings.OidcSettings`, `login.begin_login`/`complete_login`, `login_state.LoginStateStore`, `federation.sign_rp_entity_configuration`, `federation.jose`, `identity.select_identifier`, `redirect.is_safe_redirect`.
- Produces:
  - `is_safe_redirect(value: str, allowed_hosts: list[str]) -> str` — **verbatim** aus dem SAML-Package gespiegelt.
  - `build_router(rp: OidcRP) -> APIRouter` mit:
    - `GET /.well-known/openid-federation` → signierte RP Entity Configuration (`application/entity-statement+jwt`).
    - `GET /login?op=<op_entity_id>&next=/app` → `begin_login` → 303-Redirect zur Authorization-URL.
    - `GET /callback?code=&state=` → `state` aus dem Store poppen (fehlt → 400), `complete_login` → `on_authenticated(request, identity, next)` → dessen Response.
  - `OidcRP`-Fassade: `__init__(settings, *, on_authenticated=None, http_client=None)` lädt Fed-Keys aus `settings.fed_jwks`, hält `LoginStateStore`, `httpx.AsyncClient`, `.router`, `.mount(app)`, `.identifier(identity)`, `.aclose()`. Default-`on_authenticated`: `RedirectResponse(is_safe_redirect(next, allowed_hosts), 303)`.
  - Der erste Fed-Signing-Key wird aus `settings.fed_jwks` als erster privater Key bestimmt.

- [ ] **Step 1: Failing tests schreiben**

`tests/test_redirect.py`:

```python
"""Tests for the open-redirect guard."""

from fastapi_auth.openid.redirect import is_safe_redirect


def test_local_paths_pass():
    assert is_safe_redirect("/app", []) == "/app"


def test_protocol_relative_rejected():
    assert is_safe_redirect("//evil.example", []) == "/"
    assert is_safe_redirect("/\\evil.example", []) == "/"


def test_control_chars_rejected():
    assert is_safe_redirect("/app\nSet-Cookie: x", []) == "/"


def test_absolute_url_only_if_allowlisted():
    assert is_safe_redirect("https://ok.example/x", ["ok.example"]) == "https://ok.example/x"
    assert is_safe_redirect("https://evil.example/x", ["ok.example"]) == "/"
```

`tests/test_router.py`:

```python
"""Router/facade tests via FastAPI TestClient over the OP+federation double."""

import respx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from urllib.parse import parse_qs, urlparse

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture


def _rp(op: OpFixture, on_auth=None) -> OidcRP:
    settings = OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=_priv(op),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
    )
    # Inject a fixed clock consistent with OpFixture(now=NOW) so exp/iat checks pass.
    return OidcRP(settings, on_authenticated=on_auth, clock=lambda: NOW + 10)


def _priv(op: OpFixture) -> dict:
    return KeySet([op.rp_fed_key]).as_dict(private=True)


def test_well_known_serves_signed_entity_configuration():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/.well-known/openid-federation")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/entity-statement+jwt")
    claims = jose.verify_signature(resp.text, jose.load_keyset(op_rp_public(op)), algorithms=["RS256"])
    assert claims["iss"] == claims["sub"] == RP_ENTITY
    assert claims["metadata"]["openid_relying_party"]["redirect_uris"] == [f"{RP_ENTITY}/openid/callback"]


def op_rp_public(op: OpFixture) -> dict:
    return jose.public_jwks(KeySet([op.rp_fed_key]))


def test_login_redirects_to_op_authorization():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        resp = client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
    assert resp.status_code == 303
    parsed = urlparse(resp.headers["location"])
    assert parsed.path == "/authorize"
    assert parse_qs(parsed.query)["client_id"] == [RP_ENTITY]


def test_callback_invokes_on_authenticated():
    op = OpFixture()
    captured = {}

    async def on_auth(request: Request, identity: FederatedIdentity, next_url: str):
        captured["sub"] = identity.sub
        captured["next"] = next_url
        return JSONResponse({"ok": True})

    rp = _rp(op, on_auth=on_auth)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        # Capture the login state's value + nonce BEFORE the callback pops it, and
        # bind the OP's id_token to that exact nonce.
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001 - test introspection
        nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
        router.post(f"{OP_ENTITY}/token").respond(
            200,
            json={"access_token": "at", "id_token": op.id_token(nonce=nonce), "token_type": "Bearer"},
        )
        cb = client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
    assert cb.status_code == 200
    assert captured["sub"] == "u1"
    assert captured["next"] == "/app"
```

> **Hinweis für die Umsetzung:** Der TestClient und die ausgehenden httpx-Calls (OP) laufen im selben respx-Kontext. Der `op.id_token(nonce=...)` muss an die im `LoginState` gespeicherte `nonce` gebunden sein — deshalb wird die `nonce` im Test aus dem Store gelesen (`_only_nonce`). Falls `time`/`now` im Router nicht injizierbar ist: der Router nutzt Realzeit; die Testdouble-Statements/-Token nutzen `NOW`, aber `resolve_and_validate`/`validate_id_token` mit `leeway` und Realzeit-`now=None` würden die `NOW`-basierten `exp` als abgelaufen sehen. Setze deshalb im Testdouble `now` NICHT auf die Vergangenheit, sondern lasse `OpFixture.now` auf einen Zeitpunkt nahe „jetzt" zeigen ODER injiziere `now` in den Router über die Fassade (empfohlen: `OidcRP` akzeptiert optional `clock: Callable[[], int]` für Tests). **Umsetzungsentscheidung:** `OidcRP.__init__(..., clock=None)`; Default `clock=jose.now_epoch`; Router/`begin_login`/`complete_login` erhalten `now=self._clock()`. Die Tests konstruieren `OpFixture(now=<clock-Wert>)` konsistent mit dem injizierten Clock — hier: injiziere `clock=lambda: NOW+10` in `_rp` und baue `OpFixture()` mit `NOW`.

Passe `_rp` entsprechend an:

```python
    return OidcRP(settings, on_authenticated=on_auth, clock=lambda: NOW + 10)
```

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/test_redirect.py tests/test_router.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: `redirect.py` (gespiegelt) implementieren**

`src/fastapi_auth/openid/redirect.py`:

```python
"""Resolve a post-login redirect target safely (open-redirect protection).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from urllib.parse import urlparse


def is_safe_redirect(value: str, allowed_hosts: list[str]) -> str:
    r"""Return value if it is a safe local path or an allow-listed absolute URL, else '/'.

    Local paths must be single-slash-prefixed and must not start with '//' or '/\\'
    (both resolve to a cross-origin URL in browsers). Values containing ASCII
    control characters are rejected outright (defense in depth against
    header/response-splitting or smuggling tricks upstream parsers might miss).
    """
    if any(ord(c) < 0x20 for c in value):
        return "/"
    if value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    parsed = urlparse(value)
    allowed_hosts_lower = {h.lower() for h in allowed_hosts}
    if parsed.scheme in ("http", "https") and parsed.hostname in allowed_hosts_lower:
        return value
    return "/"
```

- [ ] **Step 4: `rp.py` (Fassade) implementieren**

`src/fastapi_auth/openid/rp.py`:

```python
"""OidcRP facade: wires settings, federation keys, login state and router.

Composition root for one configured relying party. The user-session layer is
Plan 4; until then the callback delegates to a pluggable ``on_authenticated``
seam (default: redirect to the validated ``next`` target).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.login_state import LoginStateStore
from fastapi_auth.openid.redirect import is_safe_redirect
from fastapi_auth.openid.router import build_router
from fastapi_auth.openid.settings import OidcSettings

OnAuthenticated = Callable[[Request, FederatedIdentity, str], Awaitable[Response]]


def _first_private_key(jwks: dict[str, object]) -> Key:
    keyset = KeySet.import_key_set(jwks)
    for key in keyset.keys:
        material = key.as_dict(private=True)
        if any(param in material for param in ("d", "k")):
            return key
    raise ValueError("fed_jwks contains no private signing key")


class OidcRP:
    """Composition root: one configured OpenID Connect relying party."""

    def __init__(
        self,
        settings: OidcSettings,
        *,
        on_authenticated: OnAuthenticated | None = None,
        http_client: object | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """Build federation keys, the login-state store and the router from settings."""
        import httpx

        self.settings = settings
        # Package-internal but attribute-public (no leading underscore) so the
        # router factory can read them without triggering ruff SLF001.
        self.fed_key = _first_private_key(settings.fed_jwks)
        self.fed_public = jose.public_jwks(KeySet([self.fed_key]))
        self.state_store = LoginStateStore(ttl=settings.login_state_ttl)
        self.http_client = http_client if http_client is not None else httpx.AsyncClient()
        self.clock = clock if clock is not None else jose.now_epoch
        self.on_authenticated = on_authenticated or self._default_on_authenticated
        self.router = build_router(self)

    async def _default_on_authenticated(
        self, request: Request, identity: FederatedIdentity, next_url: str
    ) -> Response:
        target = is_safe_redirect(next_url, self.settings.allowed_redirect_hosts)
        return RedirectResponse(target, status_code=303)

    def identifier(self, identity: FederatedIdentity) -> str | None:
        """Return this RP's chosen stable identifier (sub, with fallbacks)."""
        return select_identifier(identity, "sub", ["eppn", "preferred_username"])

    def mount(self, app: FastAPI, **kwargs: object) -> None:
        """Include this RP's router under ``settings.mount_path``."""
        app.include_router(self.router, prefix=self.settings.mount_path, **kwargs)

    async def aclose(self) -> None:
        """Close the shared httpx client (call from a FastAPI lifespan shutdown)."""
        await self._client.aclose()


__all__ = ["OidcRP"]
```

- [ ] **Step 5: `router.py` implementieren**

`src/fastapi_auth/openid/router.py`:

```python
"""FastAPI router factory for the OpenID Connect relying-party endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from fastapi_auth.openid.federation.entity_configuration import sign_rp_entity_configuration
from fastapi_auth.openid.oidc import login
from fastapi_auth.openid.oidc.errors import OidcError
from fastapi_auth.openid.redirect import is_safe_redirect

if TYPE_CHECKING:
    from fastapi_auth.openid.rp import OidcRP

_ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt"


def build_router(rp: OidcRP) -> APIRouter:
    """Build the well-known/login/callback routes bound to this OidcRP."""
    router = APIRouter()
    settings = rp.settings

    @router.get("/.well-known/openid-federation")
    async def entity_configuration() -> Response:
        rp_metadata = dict(settings.rp_metadata)
        rp_metadata.setdefault("redirect_uris", [settings.callback_url])
        token = sign_rp_entity_configuration(
            entity_id=settings.entity_id,
            fed_jwks_public=rp.fed_public,
            fed_signing_key=rp.fed_key,
            authority_hints=settings.authority_hints,
            rp_metadata=rp_metadata,
        )
        return Response(token, media_type=_ENTITY_STATEMENT_MEDIA_TYPE)

    @router.get("/login")
    async def login_endpoint(op: str, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, settings.allowed_redirect_hosts)
        try:
            redirect = await login.begin_login(
                http_client=rp.http_client,
                settings=settings,
                fed_signing_key=rp.fed_key,
                op_entity_id=op,
                next_url=safe_next,
                state_store=rp.state_store,
                now=rp.clock(),
            )
        except OidcError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return RedirectResponse(redirect.url, status_code=303)

    @router.get("/callback")
    async def callback(request: Request, state: str, code: str = "") -> Response:
        login_state = rp.state_store.pop(state, now=rp.clock())
        if login_state is None:
            raise HTTPException(status_code=400, detail="unknown or expired login state")
        if not code:
            raise HTTPException(status_code=400, detail="missing authorization code")
        try:
            identity = await login.complete_login(
                http_client=rp.http_client,
                settings=settings,
                fed_signing_key=rp.fed_key,
                login_state=login_state,
                code=code,
                now=rp.clock(),
            )
        except OidcError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return await rp.on_authenticated(request, identity, login_state.next_url)

    return router
```

- [ ] **Step 6: Tests grün laufen lassen**

Run: `uv run pytest tests/test_redirect.py tests/test_router.py -v`
Expected: alle passed. (Router-Tests: der injizierte `clock=lambda: NOW+10` und `OpFixture(now=NOW)` müssen konsistent sein, damit `exp`-Prüfungen mit `clock_skew` bestehen.)

- [ ] **Step 7: Lint**

Run: `make lint`
Expected: exit 0. `OidcRP` führt `fed_key`, `fed_public`, `http_client`, `state_store`, `clock`, `on_authenticated` bewusst als unterstrichfreie, paket-intern öffentliche Attribute (der Router liest sie ohne `SLF001`). Nur die Test-Introspektion auf `rp.state_store._entries` greift auf ein privates Feld von `LoginStateStore` zu und trägt dort `# noqa: SLF001`.

- [ ] **Step 8: Commit**

```bash
git add src/fastapi_auth/openid/redirect.py src/fastapi_auth/openid/router.py src/fastapi_auth/openid/rp.py tests/test_redirect.py tests/test_router.py
git commit -m "feat(oidc): Router (login/callback/well-known) + OidcRP-Fassade + Redirect-Guard"
```

---

## Task 8: Public API + End-to-End-Integration

**Files:**
- Modify: `src/fastapi_auth/openid/__init__.py` (Re-Exports ergänzen)
- Test: `tests/test_public_api.py`

**Interfaces:**
- Produces: Re-Exports in `fastapi_auth.openid`: zusätzlich zu Plan 1 (`FederatedIdentity`, `map_claims`, `select_identifier`) nun `OidcRP`, `OidcSettings`. Federation-Schicht bleibt unter `fastapi_auth.openid.federation`.

- [ ] **Step 1: Failing test schreiben**

`tests/test_public_api.py`:

```python
"""Public API surface of fastapi_auth.openid."""

from fastapi_auth import openid


def test_public_reexports_present():
    for name in ("FederatedIdentity", "map_claims", "select_identifier", "OidcRP", "OidcSettings"):
        assert hasattr(openid, name), name


def test_version_present():
    assert openid.__version__


def test_federation_entry_points_importable():
    from fastapi_auth.openid.federation import resolve_and_validate, sign_rp_entity_configuration

    assert callable(resolve_and_validate)
    assert callable(sign_rp_entity_configuration)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_public_api.py -v`
Expected: FAIL (`OidcRP`/`OidcSettings` fehlen im Namespace).

- [ ] **Step 3: Public API erweitern**

Ersetze den Inhalt von `src/fastapi_auth/openid/__init__.py` durch:

```python
"""Federated OpenID Connect Relying Party for FastAPI.

Public entry point of the ``fastapi_auth.openid`` package.
Import via ``from fastapi_auth import openid``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.mapper import map_claims
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings

__all__ = [
    "FederatedIdentity",
    "OidcRP",
    "OidcSettings",
    "__version__",
    "map_claims",
    "select_identifier",
]

__version__ = "0.1.0.dev0"
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/test_public_api.py -v`
Expected: alle passed.

- [ ] **Step 5: Ganze Suite + Lint**

Run:

```bash
uv run pytest
uv run ruff format .
uv run ruff check .
uv run ty check src tests
make lint
```

Expected: pytest alle passed (Plan 1 + 2 + 3); ruff „All checks passed!"; `ty` ohne Fehler; `make lint` exit 0. Falls `ruff format .` Doku-Markdown anfasst: NICHT committen (nur `src`/`tests`), wie in Plan 2.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/__init__.py tests/test_public_api.py
git commit -m "feat(oidc): OidcRP/OidcSettings in die Public API aufnehmen"
```

---

## Self-Review

**Spec-Abdeckung (Plan 3 vs. Design §2/§3 + Roadmap Plan 3):**
- Settings (Entity/Keys/Trust-Anchors/OIDC) → Task 1 ✅
- PKCE (S256) + transienter Login-State → Task 2 ✅
- Signierter Request Object (JAR, Automatic Registration, §12.1.1.1) → Task 3 ✅
- `private_key_jwt`-Client-Assertion (`aud`=OP-Entity-ID) + Token-Tausch + userinfo → Task 4 ✅
- ID-Token-Validierung (Signatur gegen Trust-Chain-JWKS + iss/aud/azp/nonce/exp), adversarial → Task 5 ✅
- Login-Orchestrierung (begin/complete) → FederatedIdentity via `map_claims` → Task 6 ✅
- Router (login/callback/well-known via `sign_rp_entity_configuration`) + `OidcRP`-Fassade + Open-Redirect-Guard → Task 7 ✅
- Public API (`OidcRP`, `OidcSettings`) + End-to-End → Task 8 ✅

**Bewusst NICHT (dokumentiert):** Session-Persistenz (Plan 4, `on_authenticated`-Naht), PAR (v1: JAR), Discovery/WAYF (Plan 5), Logout/`at_hash`/`jwks_uri`-Fetch/Explicit Registration/Trust Marks (später). Kein stiller Skip.

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt enthält vollständigen, lauffähigen Code (joserfc/httpx-API in Plan 2 verifiziert). Zwei bewusst markierte Umsetzungsentscheidungen (Router-`clock`-Injektion; `OidcRP`-Accessor-Properties statt `_private`-Zugriff) sind explizit als verbindlich ausformuliert, nicht als offene Frage.

**Typ-Konsistenz:** `OidcSettings` (T1) ⇄ `LoginState`/`LoginStateStore` (T2) ⇄ `request_object` (T3) ⇄ `token` (T4) ⇄ `id_token` (T5) ⇄ `login.begin_login`/`complete_login` (T6) ⇄ `router`/`OidcRP` (T7) ⇄ Public API (T8). `LoginState.op_metadata` (die aufgelösten `openid_provider`-Metadaten aus T6) wird in `complete_login` (issuer/token_endpoint/jwks) und im Router konsumiert. Der `clock`/`now`-Pfad ist durchgängig: `OidcRP.clock` → Router → `begin_login`/`complete_login` → `resolve_and_validate`/`validate_id_token`. Das `tests/oidc/conftest.py`-Double (T6) wird von T7 wiederverwendet (`OpFixture`, `OP_ENTITY`, `RP_ENTITY`, `NOW`).

**Sicherheits-Selbstprüfung:** Algorithmen gepinnt (`id_token_signing_alg_values`, RS256/ES256); PKCE S256; `state`/`nonce` zufällig + einmalig (Store-`pop`); Request-Object/Client-Assertion-`aud` = OP-Entity-ID (Spec-konform, kein Token-Endpoint-URL-Footgun); ID-Token gegen Trust-Chain-JWKS; Open-Redirect-Guard auf `next` an beiden Eintrittspunkten; keine Secrets im Log.

---

## Nächster Meilenstein

- **Plan 4 — Session-Backends:** Cookie- (Default) + JWT-Session (joserfc) + Store (Memory/Redis/Postgres,
  optionale Extras) + Factory; Verdrahtung in `OidcRP` über die `on_authenticated`-Naht
  (`SessionBackend.establish` + Redirect) sowie `current_user`/`optional_user`-Dependencies — gespiegelt
  vom SAML-Package.
