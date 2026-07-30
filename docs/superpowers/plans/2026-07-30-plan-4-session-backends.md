# Plan 4 — Session-Backends (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die Login-Session als FastAPI-Baustein ergänzen — ein `SessionBackend` (Cookie-Default,
JWT opt-in über **joserfc**) über einem `Store` (Memory-Default, Redis/Postgres als optionale Extras),
eine Factory, und die Verdrahtung in `OidcRP`: der Callback etabliert nach erfolgreichem Login eine
Session (über die `on_authenticated`-Naht aus Plan 3), plus `current_user`/`optional_user`-Dependencies.

**Architecture:** **Gespiegelt vom fertigen SAML-Package** (`fastapi_auth.saml.session`), mit zwei
bewussten Abweichungen für dieses Paket: (1) das JWT-Backend signiert/prüft mit **joserfc** statt
PyJWT (das ganze Paket nutzt joserfc), (2) der `Store` trägt nur die **Session**-Methoden
(`save_session`/`load_session`/`delete_session`/`aclose`) — die SAML-spezifischen
`outstanding`/`seen_assertion`-Methoden entfallen, weil der transiente OIDC-Login-State bereits der
`LoginStateStore` (Plan 3) ist. Der Cookie-Backend hält eine serverseitige Session, adressiert über
eine mit `itsdangerous` signierte Session-ID; das JWT-Backend ist zustandslos. `OidcRP` baut Store +
Backend aus den Settings über eine Factory und ersetzt seinen Default-`on_authenticated` durch
„Session etablieren → Redirect".

**Tech Stack:** Python 3.12+, joserfc 1.7+ (JWT-Session), itsdangerous (Cookie-Signatur), Pydantic v2 +
pydantic-settings, FastAPI, pytest + pytest-asyncio, fakeredis (Test), aiosqlite/SQLModel (Test),
ruff, ty, uv. Wiederverwendet Plan 1 (`FederatedIdentity`, `select_identifier`) und Plan 3
(`OidcRP`, `OidcSettings`, `on_authenticated`-Naht).

## Global Constraints

- Distribution: `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header in **jeder** Quellcodedatei unter `src/`.
- Python-Floor: `>=3.12`. async-first: alle Backend-/Store-Methoden sind `async`.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung. Bei joserfc-TypedDict-vs-`dict`- oder SQLAlchemy-Instrumented-Attribute-Grenzen ist ein enger `cast(...)`/`# ty: ignore[...]` (mit Begründung, wie im SAML-Package) erlaubt.
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren. `make lint` (scoped `src tests`) MUSS exit 0.
- **Sicherheits-Kern:** Session-Cookies sind `HttpOnly`, `Secure` (per `cookie_secure`, Default True), `SameSite=lax`. Die serverseitige Session-ID (Cookie-Backend) ist mit `itsdangerous` signiert + zeitbegrenzt. Das JWT-Backend pinnt **genau eine** `jwt_alg` beim Signieren UND Verifizieren (Alg-Confusion geschlossen), signiert via **joserfc**, nie `none`; `exp` wird geprüft. Keine Secrets/Token loggen. Symmetrische JWT-Secrets brauchen ≥32 Bytes.
- **Kein selbstgebautes JOSE/Krypto:** JWT über `joserfc.jwt.encode`/`decode`, Cookie-Signatur über `itsdangerous`. Keine handgerollten Signaturen.
- Feld-Ausrichtung: `Store` persistiert `FederatedIdentity` via `model_dump_json`/`model_validate_json`. Struktur/Benennung spiegeln das SAML-Package (`SessionBackend`, `Store`, `MemoryStore`, `CookieBackend`, `JWTBackend`, `make_store`, `make_backend`).
- Niemals `git push`. Commits auf `main` sind für dieses greenfield-Repo ausdrücklich erlaubt.
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).

### Bewusst NICHT in Plan 4 (YAGNI / Folgepläne)

- **Logout-Route** (`/logout` + `end_session_endpoint`): Plan 5. Plan 4 liefert `SessionBackend.revoke` als Baustein, aber keine Route.
- **Discovery/WAYF:** Plan 5.
- **Login-State im Store persistieren** (Multi-Worker-tauglicher `LoginStateStore`): offen gelassen; Plan 4 lässt den `LoginStateStore` (Plan 3) prozess-lokal. Dokumentierter Verzicht.
- **Router-Negativpfad-Tests aus Plan 3** (OidcError→502/401, unbekannter/abgelaufener state→400): werden hier NICHT nachgezogen (separater kleiner Folgeschritt), um Plan 4 fokussiert zu halten.

## Verifizierte Vorlage (SAML-Package — verbindlich gespiegelt)

Die Referenzimplementierung liegt unter `~/workspaces/LMU/wallet/fastapi-auth-federated-saml/src/fastapi_auth/saml/session/` (`base.py`, `cookie.py`, `jwt.py`, `store.py`, `redis_store.py`, `postgres_store.py`) und `factory.py`. Dieser Plan spiegelt sie mit den o. g. Abweichungen; die Code-Blöcke unten sind bereits angepasst.

**joserfc-JWT (Ersatz für PyJWT):** `from joserfc import jwt as jose_jwt`; `from joserfc.jwk import OctKey, KeySet, Key`. Signieren: `jose_jwt.encode({"alg": alg, "typ": "JWT"}, payload, key, algorithms=[alg]) -> str`. Verifizieren: `jose_jwt.decode(token, key, algorithms=[alg])` → Objekt mit `.claims`; wirft `joserfc.errors.BadSignatureError`/`DecodeError`/`InvalidKeyIdError` bei ungültig. `exp` wird NICHT automatisch geprüft → explizit prüfen. Symmetrisch: `OctKey.import_key(secret)`. Asymmetrisch: `jose.load_keyset(jwt_jwks)` + ersten privaten Key zum Signieren, KeySet (public) zum Verifizieren (kid-Match). **Vor der Umsetzung im venv die exakte `OctKey.import_key`-Signatur bestätigen** (wie in Plan 2/3 bei joserfc-Kanten) und bei Abweichung anpassen.

## File Structure

```text
pyproject.toml                                        # itsdangerous (core); redis/postgres extras; dev: fakeredis, aiosqlite
src/fastapi_auth/openid/settings.py                   # + Session/Store/JWT-Felder + jwt-Key-Properties + Validator
src/fastapi_auth/openid/session/__init__.py
src/fastapi_auth/openid/session/base.py               # SessionBackend Protocol
src/fastapi_auth/openid/session/store.py              # Store Protocol + MemoryStore (session-only)
src/fastapi_auth/openid/session/cookie.py             # CookieBackend (itsdangerous + Store)
src/fastapi_auth/openid/session/jwt.py                # JWTBackend (joserfc)
src/fastapi_auth/openid/session/redis_store.py        # RedisStore (optional)
src/fastapi_auth/openid/session/postgres_store.py     # PostgresStore (optional)
src/fastapi_auth/openid/factory.py                    # make_store / make_backend
src/fastapi_auth/openid/rp.py                          # OidcRP: Store+Backend + session-establishing on_authenticated + current_user/optional_user
tests/session/__init__.py
tests/session/test_store.py
tests/session/test_cookie.py
tests/session/test_jwt_backend.py
tests/session/test_jwt_asymmetric.py
tests/session/test_stores_optional.py
tests/test_factory.py
tests/test_settings.py                                # + Session-Settings-Tests (bestehende Datei erweitern)
tests/test_session_flow.py                            # End-to-End: login -> callback -> Session -> current_user
```

---

## Task 1: Session-Settings + Dependencies

**Files:**
- Modify: `pyproject.toml` (core dep `itsdangerous`; extras `redis`, `postgres`; dev `fakeredis`, `aiosqlite`)
- Modify: `src/fastapi_auth/openid/settings.py` (Session/Store/JWT-Felder + Properties + Validator)
- Modify: `tests/test_settings.py` (Session-Settings-Tests ergänzen)

**Interfaces:**
- Consumes: `OidcSettings` (Plan 1/3).
- Produces (neue Felder/Members auf `OidcSettings`):
  - `session_cookie_name: str = "fa_openid_session"`, `session_secret: str | None = None`, `session_ttl: int = 28800`, `cookie_secure: bool = True`.
  - `backend: Literal["cookie", "jwt"] = "cookie"`, `store: Literal["memory", "redis", "postgres"] = "memory"`, `redis_url: str = "redis://localhost:6379/0"`, `db_url: str = "sqlite+aiosqlite:///:memory:"`.
  - `jwt_alg: str = "HS256"`, `jwt_ttl: int = 3600`, `jwt_secret: str | None = None`, `jwt_jwks: dict[str, object] | None = None`, `jwt_attributes: list[str] | None = None`.
  - `jwt_is_symmetric() -> bool`; `jwt_signing_secret -> str`; `_check_jwt_secret_strength`-Validator (nur bei `backend == "jwt"`).

- [ ] **Step 1: `itsdangerous` + Extras + Dev-Deps aufnehmen**

In `pyproject.toml`: `itsdangerous>=2.2` in `[project].dependencies` ergänzen. `[project.optional-dependencies]` um Extras erweitern und dev ergänzen:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "anyio>=4",
    "respx>=0.21",
    "httpx>=0.27",
    "fakeredis>=2.23",
    "aiosqlite>=0.20",
    "sqlmodel>=0.0.22",
    "ruff>=0.6",
    "ty",
    "pdbp>=1.5",
]
redis = ["redis>=5"]
postgres = ["sqlmodel>=0.0.22", "asyncpg>=0.29"]
```

(Falls der `dev`-Block bereits Einträge hat: die drei neuen — `fakeredis`, `aiosqlite`, `sqlmodel` — hinzufügen, Rest unverändert lassen. Bestehende Einträge nicht entfernen.)

Run: `uv pip install -U -e ".[dev]"`
Expected: itsdangerous, fakeredis, aiosqlite, sqlmodel installiert.

- [ ] **Step 2: Failing test schreiben**

An `tests/test_settings.py` anhängen (Importe oben ggf. ergänzen — `OidcSettings` ist bereits importiert):

```python
def test_session_defaults():
    s = OidcSettings(**_BASE)
    assert s.session_cookie_name == "fa_openid_session"
    assert s.session_ttl == 28800
    assert s.cookie_secure is True
    assert s.backend == "cookie"
    assert s.store == "memory"
    assert s.jwt_alg == "HS256"


def test_jwt_symmetric_requires_strong_secret():
    with pytest.raises(ValidationError, match="32"):
        OidcSettings(**cast(dict[str, Any], {**_BASE, "backend": "jwt", "session_secret": "short"}))


def test_jwt_symmetric_accepts_strong_secret():
    data = cast(dict[str, Any], {**_BASE, "backend": "jwt", "session_secret": "s" * 32})
    s = OidcSettings(**data)
    assert s.backend == "jwt"
    assert s.jwt_is_symmetric() is True
    assert s.jwt_signing_secret == "s" * 32


def test_jwt_secret_overrides_session_secret_for_signing():
    data = cast(dict[str, Any], {**_BASE, "session_secret": "x" * 32, "jwt_secret": "y" * 40})
    assert OidcSettings(**data).jwt_signing_secret == "y" * 40


def test_jwt_asymmetric_requires_jwt_jwks():
    with pytest.raises(ValidationError, match="jwt_jwks"):
        OidcSettings(**cast(dict[str, Any], {**_BASE, "backend": "jwt", "jwt_alg": "RS256"}))


def test_jwt_asymmetric_accepts_jwks():
    data = cast(
        dict[str, Any],
        {**_BASE, "backend": "jwt", "jwt_alg": "RS256", "jwt_jwks": {"keys": [{"kty": "RSA"}]}},
    )
    s = OidcSettings(**data)
    assert s.jwt_is_symmetric() is False


def test_store_selection_fields():
    s = OidcSettings(**cast(dict[str, Any], {**_BASE, "store": "redis", "redis_url": "redis://h:6379/1"}))
    assert s.store == "redis"
    assert s.redis_url == "redis://h:6379/1"
```

- [ ] **Step 3: Test rot laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: FAIL (neue Felder/Validator fehlen).

- [ ] **Step 4: Settings erweitern**

In `src/fastapi_auth/openid/settings.py` `Literal` importieren (`from typing import Literal`) und im `OidcSettings`-Body die Session-/Store-/JWT-Felder ergänzen (nach den bestehenden Security-Feldern):

```python
    # --- session ---
    session_cookie_name: str = "fa_openid_session"
    session_secret: str | None = None
    session_ttl: int = 28800
    cookie_secure: bool = True

    # --- session backend / store selection ---
    backend: Literal["cookie", "jwt"] = "cookie"
    store: Literal["memory", "redis", "postgres"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    db_url: str = "sqlite+aiosqlite:///:memory:"

    # --- JWT backend (opt-in; joserfc) ---
    jwt_alg: str = "HS256"
    jwt_ttl: int = 3600
    jwt_secret: str | None = None
    # Asymmetric jwt_alg (RS256, ES256, EdDSA, ...): sign with the first private
    # key in jwt_jwks, verify with its public half — other services can verify
    # without being able to mint tokens.
    jwt_jwks: dict[str, object] | None = None
    # Data minimisation: when set, only these FederatedIdentity field names are
    # carried in the token's "attrs" claim.
    jwt_attributes: list[str] | None = None
```

Und die JWT-Helfer + Validator (nach den bestehenden Properties/Validator) ergänzen:

```python
    def jwt_is_symmetric(self) -> bool:
        """Return whether ``jwt_alg`` is a symmetric (HMAC) algorithm."""
        return self.jwt_alg.startswith("HS")

    @property
    def jwt_signing_secret(self) -> str:
        """Secret used to sign symmetric app JWTs (defaults to the session secret)."""
        return self.jwt_secret or self.session_secret or ""

    @model_validator(mode="after")
    def _check_jwt_secret_strength(self) -> OidcSettings:
        """Ensure the JWT backend has strong-enough key material.

        Symmetric algorithms (HS*) need a shared secret of at least 32 bytes;
        asymmetric algorithms need a ``jwt_jwks`` with a private key. Only
        enforced when ``backend == "jwt"``.
        """
        if self.backend != "jwt":
            return self
        if self.jwt_is_symmetric():
            if len(self.jwt_signing_secret.encode()) < 32:
                raise ValueError("JWT backend requires jwt_secret/session_secret of at least 32 bytes")
        elif self.jwt_jwks is None:
            raise ValueError("JWT backend with an asymmetric jwt_alg requires jwt_jwks")
        return self
```

- [ ] **Step 5: Test grün laufen lassen**

Run: `uv run pytest tests/test_settings.py -v`
Expected: alle passed (bestehende + neue).

- [ ] **Step 6: Lint + ganze Suite**

Run: `uv run pytest -q && make lint`
Expected: grün; exit 0. (Die bestehenden Plan-1/3-Tests konstruieren `OidcSettings` ohne `session_secret` — das bleibt gültig, weil `session_secret` optional ist und der Validator nur bei `backend == "jwt"` greift.)

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/fastapi_auth/openid/settings.py tests/test_settings.py
git commit -m "feat(session): OidcSettings um Session-/Store-/JWT-Felder erweitern (itsdangerous + Extras)"
```

---

## Task 2: SessionBackend + Store Protocols + MemoryStore

**Files:**
- Create: `src/fastapi_auth/openid/session/__init__.py`, `src/fastapi_auth/openid/session/base.py`, `src/fastapi_auth/openid/session/store.py`
- Test: `tests/session/__init__.py`, `tests/session/test_store.py`

**Interfaces:**
- Produces:
  - `SessionBackend` (Protocol): `async establish(identity, response) -> None`, `async load(request) -> FederatedIdentity | None`, `async revoke(request, response) -> None`.
  - `Store` (Protocol): `async save_session(sid, identity, ttl) -> None`, `async load_session(sid) -> FederatedIdentity | None`, `async delete_session(sid) -> None`, `async aclose() -> None`.
  - `MemoryStore` — In-Memory, lazy TTL-Expiry, injizierbare Clock.

- [ ] **Step 1: Failing test schreiben**

`tests/session/__init__.py`: leere Datei.

`tests/session/test_store.py`:

```python
"""Tests for the in-memory session store."""

import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.store import MemoryStore


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.asyncio
async def test_save_load_delete():
    clock = [1000.0]
    store = MemoryStore(clock=lambda: clock[0])
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.sub == "u1"
    await store.delete_session("sid")
    assert await store.load_session("sid") is None


@pytest.mark.asyncio
async def test_expired_session_is_evicted():
    clock = [1000.0]
    store = MemoryStore(clock=lambda: clock[0])
    await store.save_session("sid", _identity(), ttl=300)
    clock[0] = 2000.0
    assert await store.load_session("sid") is None


@pytest.mark.asyncio
async def test_load_unknown_returns_none():
    assert await MemoryStore().load_session("nope") is None


@pytest.mark.asyncio
async def test_aclose_is_noop():
    await MemoryStore().aclose()  # must not raise
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/session/test_store.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/session/__init__.py`:

```python
"""Session layer: backend protocol, stores, cookie/JWT backends.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/openid/session/base.py`:

```python
"""SessionBackend protocol.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Protocol

from fastapi import Request, Response

from fastapi_auth.openid.identity.model import FederatedIdentity


class SessionBackend(Protocol):
    """Establishes, loads and revokes a login session on a response/request."""

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Establish a session for the identity and write it to the response."""
        ...

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Load and return the identity from the request, or None if not authenticated."""
        ...

    async def revoke(self, request: Request, response: Response) -> None:
        """Revoke the session and clear it from the response."""
        ...
```

`src/fastapi_auth/openid/session/store.py`:

```python
"""In-memory Store + Store protocol (ttl-based, injectable clock, lazy expiry).

Unlike the SAML package, this Store carries only the session methods: the OIDC
in-flight authorization state lives in the separate LoginStateStore (Plan 3).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from fastapi_auth.openid.identity.model import FederatedIdentity


class Store(Protocol):
    """Session storage backend."""

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        ...

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        ...

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        ...

    async def aclose(self) -> None:
        """Release any resources held by the store (connections, pools, ...)."""
        ...


class MemoryStore:
    """Non-persistent Store (single process) with lazy TTL expiry."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Initialize an empty store using the given clock for TTL expiry."""
        self._clock = clock
        self._sessions: dict[str, tuple[FederatedIdentity, float]] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        self._sessions[sid] = (identity, self._clock() + ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        item = self._sessions.get(sid)
        if item is None:
            return None
        identity, expires_at = item
        if self._clock() > expires_at:
            self._sessions.pop(sid, None)
            return None
        return identity

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        self._sessions.pop(sid, None)

    async def aclose(self) -> None:
        """No-op: MemoryStore holds no external resources to release."""
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/session/test_store.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/session/__init__.py src/fastapi_auth/openid/session/base.py src/fastapi_auth/openid/session/store.py tests/session/__init__.py tests/session/test_store.py
git commit -m "feat(session): SessionBackend- + Store-Protokoll + MemoryStore (session-only)"
```

---

## Task 3: CookieBackend

**Files:**
- Create: `src/fastapi_auth/openid/session/cookie.py`
- Test: `tests/session/test_cookie.py`

**Interfaces:**
- Consumes: `Store` (Task 2), `OidcSettings`, `FederatedIdentity`, itsdangerous.
- Produces: `CookieBackend(settings, store)` — serverseitige Session, adressiert über eine mit `URLSafeTimedSerializer` signierte Session-ID im Cookie. `establish` erzeugt eine zufällige `sid`, speichert die Identität im Store und setzt das signierte Cookie (`HttpOnly`, `Secure`, `SameSite=lax`, `max_age=session_ttl`). `load` liest/prüft das Cookie und lädt aus dem Store. `revoke` löscht Store-Eintrag + Cookie. Ungültige/abgelaufene/verfälschte Cookies → `None`.

- [ ] **Step 1: Failing test schreiben**

`tests/session/test_cookie.py`:

```python
"""Tests for the signed-cookie session backend."""

import pytest
from fastapi import Request, Response

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.cookie import CookieBackend
from fastapi_auth.openid.session.store import MemoryStore
from fastapi_auth.openid.settings import OidcSettings

_JWKS = {"keys": []}


def _settings(**over) -> OidcSettings:
    base = dict(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks=_JWKS,
        session_secret="s" * 32,
    )
    base.update(over)
    return OidcSettings(**base)  # type: ignore[arg-type]


def _request_with_cookie(name: str, value: str) -> Request:
    scope = {"type": "http", "headers": [(b"cookie", f"{name}={value}".encode())]}
    return Request(scope)


@pytest.mark.asyncio
async def test_establish_sets_cookie_and_stores_identity():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", mail=["u@lmu.de"]), response)
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()


@pytest.mark.asyncio
async def test_round_trip_load_returns_identity():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    cookie_value = _extract_cookie_value(response, settings.session_cookie_name)
    request = _request_with_cookie(settings.session_cookie_name, cookie_value)
    loaded = await backend.load(request)
    assert loaded is not None
    assert loaded.sub == "u1"


@pytest.mark.asyncio
async def test_tampered_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = _request_with_cookie(settings.session_cookie_name, "not-a-valid-signed-value")
    assert await backend.load(request) is None


@pytest.mark.asyncio
async def test_missing_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = Request({"type": "http", "headers": []})
    assert await backend.load(request) is None


@pytest.mark.asyncio
async def test_revoke_deletes_store_and_cookie():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    cookie_value = _extract_cookie_value(response, settings.session_cookie_name)
    request = _request_with_cookie(settings.session_cookie_name, cookie_value)
    revoke_response = Response()
    await backend.revoke(request, revoke_response)
    assert await backend.load(request) is None
    assert 'max-age=0' in revoke_response.headers["set-cookie"].lower() or "expires" in revoke_response.headers["set-cookie"].lower()


def _extract_cookie_value(response: Response, name: str) -> str:
    raw = response.headers["set-cookie"]
    # "<name>=<value>; Path=/; ..."
    pair = raw.split(";", 1)[0]
    return pair.split("=", 1)[1]
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/session/test_cookie.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/session/cookie.py`:

```python
"""Signed-cookie session backend (server-side session in a store).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.store import Store
from fastapi_auth.openid.settings import OidcSettings

_SALT = "fastapi-auth-openid-session"


class CookieBackend:
    """Server-side session addressed by a signed session id in a cookie."""

    def __init__(self, settings: OidcSettings, store: Store) -> None:
        """Initialize the cookie-based session backend."""
        if not settings.session_secret:
            raise ValueError("cookie session backend requires a non-empty session_secret")
        self._settings = settings
        self._store = store
        self._serializer = URLSafeTimedSerializer(settings.session_secret, salt=_SALT)

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Create a server-side session and set a signed session-id cookie."""
        sid = secrets.token_urlsafe(32)
        await self._store.save_session(sid, identity, self._settings.session_ttl)
        response.set_cookie(
            self._settings.session_cookie_name,
            self._serializer.dumps(sid),
            max_age=self._settings.session_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Load the session identity from the signed cookie, or None if invalid."""
        sid = self._read_sid(request)
        if sid is None:
            return None
        return await self._store.load_session(sid)

    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the server-side session and clear the cookie."""
        sid = self._read_sid(request)
        if sid is not None:
            await self._store.delete_session(sid)
        response.delete_cookie(self._settings.session_cookie_name)

    def _read_sid(self, request: Request) -> str | None:
        raw = request.cookies.get(self._settings.session_cookie_name)
        if not raw:
            return None
        try:
            return self._serializer.loads(raw, max_age=self._settings.session_ttl)
        except (BadSignature, SignatureExpired):
            return None
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/session/test_cookie.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/session/cookie.py tests/session/test_cookie.py
git commit -m "feat(session): CookieBackend (itsdangerous-signierte Session-ID + Store)"
```

---

## Task 4: JWTBackend (joserfc)

**Files:**
- Create: `src/fastapi_auth/openid/session/jwt.py`
- Test: `tests/session/test_jwt_backend.py`, `tests/session/test_jwt_asymmetric.py`

**Interfaces:**
- Consumes: `federation.jose` (`load_keyset`), `identity.select_identifier`, `FederatedIdentity`, `OidcSettings`, joserfc.
- Produces: `JWTBackend(settings)` — zustandslos, signiert die Identität in ein JWT (joserfc), Cookie ODER `Authorization: Bearer`. `establish` setzt das Cookie; `load` liest/prüft (Signatur gegen die gepinnte `jwt_alg` + `exp`); `revoke` löscht nur das Cookie (stateless). `jwt_attributes`-Allowlist beschränkt `attrs`. Alg-Confusion geschlossen (genau eine `jwt_alg`).
- Hilfsfunktion `_resolve_keys(settings) -> tuple[signing_key, verifying_key]` (symmetrisch: `OctKey`; asymmetrisch: erster privater Key aus `jwt_jwks` + public KeySet).

- [ ] **Step 1: Failing tests schreiben**

`tests/session/test_jwt_backend.py`:

```python
"""Tests for the stateless joserfc JWT session backend (symmetric)."""

import time

import pytest
from fastapi import Request, Response

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.settings import OidcSettings

_JWKS = {"keys": []}


def _settings(**over) -> OidcSettings:
    base = dict(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks=_JWKS,
        backend="jwt",
        session_secret="s" * 32,
    )
    base.update(over)
    return OidcSettings(**base)  # type: ignore[arg-type]


def _cookie_request(name: str, value: str) -> Request:
    return Request({"type": "http", "headers": [(b"cookie", f"{name}={value}".encode())]})


def _bearer_request(token: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})


def _cookie_value(response: Response, name: str) -> str:
    return response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]


@pytest.mark.asyncio
async def test_round_trip_via_cookie():
    settings = _settings()
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", mail=["u@lmu.de"]), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_cookie_request(settings.session_cookie_name, token))
    assert loaded is not None
    assert loaded.sub == "u1"
    assert loaded.mail == ["u@lmu.de"]


@pytest.mark.asyncio
async def test_round_trip_via_bearer():
    settings = _settings()
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.sub == "u1"


@pytest.mark.asyncio
async def test_tampered_token_returns_none():
    backend = JWTBackend(_settings())
    assert await backend.load(_bearer_request("not.a.jwt")) is None


@pytest.mark.asyncio
async def test_wrong_secret_returns_none():
    established = JWTBackend(_settings(session_secret="a" * 32))
    response = Response()
    await established.establish(FederatedIdentity(sub="u1"), response)
    token = _cookie_value(response, established._settings.session_cookie_name)  # noqa: SLF001
    other = JWTBackend(_settings(session_secret="b" * 32))
    assert await other.load(_bearer_request(token)) is None


@pytest.mark.asyncio
async def test_expired_token_returns_none():
    settings = _settings(jwt_ttl=1)
    clock = [1000]
    backend = JWTBackend(settings, clock=lambda: clock[0])
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)  # signed at t=1000, exp=1001
    token = _cookie_value(response, settings.session_cookie_name)
    clock[0] = 100000  # far past exp
    assert await backend.load(_bearer_request(token)) is None


@pytest.mark.asyncio
async def test_jwt_attributes_allowlist_restricts_attrs():
    settings = _settings(jwt_attributes=["sub"])
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", mail=["u@lmu.de"]), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.sub == "u1"
    assert loaded.mail == []  # not carried
```

`tests/session/test_jwt_asymmetric.py`:

```python
"""Tests for the joserfc JWT backend with an asymmetric jwt_alg."""

import pytest
from fastapi import Request, Response
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.settings import OidcSettings


def _bearer_request(token: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})


def _settings(jwks_private: dict) -> OidcSettings:
    return OidcSettings(  # type: ignore[arg-type]
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks={"keys": []},
        backend="jwt",
        jwt_alg="RS256",
        jwt_jwks=jwks_private,
    )


@pytest.mark.asyncio
async def test_asymmetric_round_trip():
    key = RSAKey.generate_key(key_size=2048, parameters={"kid": "sess-1"}, private=True)
    private_jwks = KeySet([key]).as_dict(private=True)
    backend = JWTBackend(_settings(private_jwks))
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", eppn="u1@lmu.de"), response)
    token = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.eppn == "u1@lmu.de"
```

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/session/test_jwt_backend.py tests/session/test_jwt_asymmetric.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

> **Umsetzungshinweis:** vor dem Schreiben `uv run python -c "from joserfc.jwk import OctKey; print(OctKey.import_key('x'*32))"` im venv ausführen, um die exakte `OctKey.import_key`-Signatur zu bestätigen; bei Abweichung anpassen. Die JWT-Signatur/-Prüfung läuft ausschließlich über `joserfc.jwt` — kein Hand-JOSE.

`src/fastapi_auth/openid/session/jwt.py`:

```python
"""Stateless JWT session backend (joserfc).

Signs the identity into a JWT (cookie or ``Authorization: Bearer``). The token
is signed, not encrypted: it carries the identity in plaintext, readable by
whoever holds it. Verification is pinned to the single configured ``jwt_alg``
(closing alg-confusion), and ``exp`` is checked explicitly. Symmetric (HS*)
signs/verifies with a shared secret; an asymmetric ``jwt_alg`` signs with the
first private key in ``jwt_jwks`` and verifies with its public half.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import Request, Response
from joserfc import jwt as jose_jwt
from joserfc.errors import BadSignatureError, DecodeError, InvalidKeyIdError
from joserfc.jwk import Key, KeySet, OctKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.settings import OidcSettings


def _first_private_key(keyset: KeySet) -> Key:
    for key in keyset.keys:
        material = key.as_dict(private=True)
        if any(param in material for param in ("d", "k")):
            return key
    raise ValueError("jwt_jwks contains no private signing key")


def _resolve_keys(settings: OidcSettings) -> tuple[Key, Key | KeySet]:
    if settings.jwt_is_symmetric():
        key = OctKey.import_key(settings.jwt_signing_secret)
        return key, key
    if settings.jwt_jwks is None:  # pragma: no cover - validator guarantees this
        raise ValueError("asymmetric jwt_alg requires jwt_jwks")
    signing = _first_private_key(jose.load_keyset(settings.jwt_jwks))
    return signing, KeySet([signing])


class JWTBackend:
    """Carries the identity in a signed JWT (cookie or Authorization: Bearer)."""

    def __init__(self, settings: OidcSettings, *, clock: Callable[[], int] | None = None) -> None:
        """Initialize the JWT backend, resolving key material once from settings.

        ``clock`` (seconds since epoch) is injectable for deterministic tests;
        it defaults to wall-clock time. It is a keyword-only constructor arg, so
        ``establish``/``load`` keep the exact ``SessionBackend`` signatures.
        """
        self._settings = settings
        self._alg = settings.jwt_alg
        self._signing_key, self._verifying_key = _resolve_keys(settings)
        self._clock: Callable[[], int] = clock if clock is not None else (lambda: int(time.time()))

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Sign the identity into a JWT and set it as the session cookie."""
        issued = self._clock()
        subject = select_identifier(identity, "sub", ["eppn", "preferred_username"])
        dump = identity.model_dump(mode="json")
        if self._settings.jwt_attributes is not None:
            attrs = {k: dump[k] for k in self._settings.jwt_attributes if k in dump}
        else:
            attrs = dump
        payload = {
            "sub": subject or "",
            "iat": issued,
            "exp": issued + self._settings.jwt_ttl,
            "attrs": attrs,
        }
        token = jose_jwt.encode(
            {"alg": self._alg, "typ": "JWT"}, payload, self._signing_key, algorithms=[self._alg]
        )
        response.set_cookie(
            self._settings.session_cookie_name,
            token,
            max_age=self._settings.jwt_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Read and verify the JWT from the cookie or Bearer header, or None if invalid."""
        token = self._token_from(request)
        if token is None:
            return None
        try:
            decoded = jose_jwt.decode(token, self._verifying_key, algorithms=[self._alg])
        except (BadSignatureError, DecodeError, InvalidKeyIdError, ValueError):
            return None
        claims = decoded.claims
        moment = self._clock()
        exp = claims.get("exp")
        if not isinstance(exp, int) or exp < moment:
            return None
        attrs = claims.get("attrs", {})
        if not isinstance(attrs, dict):
            return None
        return FederatedIdentity.model_validate(attrs)

    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the session cookie (stateless: no server-side invalidation)."""
        response.delete_cookie(self._settings.session_cookie_name)

    def _token_from(self, request: Request) -> str | None:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return request.cookies.get(self._settings.session_cookie_name)
```

> **Hinweis:** `establish`/`load` haben exakt die `SessionBackend`-Protocol-Signaturen (`establish(identity, response)` / `load(request)`) — die Zeitquelle ist ein **konstruktor-injizierter** `clock` (keyword-only, Default Wall-Clock), sodass Tests deterministisch bleiben, ohne die Protocol-Signaturen zu verändern (analog `MemoryStore`). `make_backend` konstruiert `JWTBackend(settings)` mit dem Default-Clock; nur Tests injizieren einen `clock`.

- [ ] **Step 4: Tests grün laufen lassen**

Run: `uv run pytest tests/session/test_jwt_backend.py tests/session/test_jwt_asymmetric.py -v`
Expected: alle passed.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/session/jwt.py tests/session/test_jwt_backend.py tests/session/test_jwt_asymmetric.py
git commit -m "feat(session): JWTBackend ueber joserfc (HS*/asymmetrisch, Cookie/Bearer, exp-Pin)"
```

---

## Task 5: RedisStore + PostgresStore (optionale Extras)

**Files:**
- Create: `src/fastapi_auth/openid/session/redis_store.py`, `src/fastapi_auth/openid/session/postgres_store.py`
- Test: `tests/session/test_stores_optional.py`

**Interfaces:**
- Produces (session-only, spiegeln SAML ohne outstanding/seen):
  - `RedisStore(client)` + `RedisStore.from_url(url)` — Sessions als Keys mit nativem TTL (`SET ex`).
  - `PostgresStore(engine)` + `PostgresStore.from_url(url)` + `create_all()` — SQLModel-Tabelle `OpenidSession(sid PK, data, expires_at)`.

- [ ] **Step 1: Failing test schreiben**

`tests/session/test_stores_optional.py`:

```python
"""Tests for the optional Redis/Postgres session stores (fakeredis / aiosqlite)."""

import fakeredis.aioredis
import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.postgres_store import PostgresStore
from fastapi_auth.openid.session.redis_store import RedisStore


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.asyncio
async def test_redis_store_round_trip():
    store = RedisStore(fakeredis.aioredis.FakeRedis())
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.sub == "u1"
    await store.delete_session("sid")
    assert await store.load_session("sid") is None
    await store.aclose()


@pytest.mark.asyncio
async def test_postgres_store_round_trip():
    from sqlalchemy.ext.asyncio import create_async_engine

    store = PostgresStore(create_async_engine("sqlite+aiosqlite:///:memory:"))
    await store.create_all()
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.mail == ["u@lmu.de"]
    await store.delete_session("sid")
    assert await store.load_session("sid") is None
    await store.aclose()


@pytest.mark.asyncio
async def test_postgres_store_expired_returns_none():
    from sqlalchemy.ext.asyncio import create_async_engine

    store = PostgresStore(create_async_engine("sqlite+aiosqlite:///:memory:"))
    await store.create_all()
    await store.save_session("sid", _identity(), ttl=-1)  # already expired
    assert await store.load_session("sid") is None
    await store.aclose()
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/session/test_stores_optional.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: `redis_store.py` implementieren**

`src/fastapi_auth/openid/session/redis_store.py`:

```python
"""Redis-backed session Store (redis.asyncio, native key TTL).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

from fastapi_auth.openid.identity.model import FederatedIdentity


class RedisStore:
    """Session Store backed by Redis; sessions are keys with native TTL."""

    def __init__(self, client: Any, *, session_prefix: str = "fa:oidc:sess:") -> None:
        """Wrap an existing ``redis.asyncio.Redis``-compatible client."""
        self._r = client
        self._sp = session_prefix

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        """Build a RedisStore from a redis:// URL, lazily importing redis.asyncio."""
        try:
            import redis.asyncio as redis_async
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "RedisStore requires the 'redis' extra: "
                "pip install 'fastapi-auth-openid-federated[redis]'"
            )
            raise RuntimeError(msg) from err
        return cls(redis_async.from_url(url))

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        await self._r.set(f"{self._sp}{sid}", identity.model_dump_json(), ex=ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        raw = await self._r.get(f"{self._sp}{sid}")
        if raw is None:
            return None
        return FederatedIdentity.model_validate_json(raw)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        await self._r.delete(f"{self._sp}{sid}")

    async def aclose(self) -> None:
        """Close the wrapped Redis client, releasing its connection pool."""
        await self._r.aclose()
```

- [ ] **Step 4: `postgres_store.py` implementieren**

`src/fastapi_auth/openid/session/postgres_store.py`:

```python
"""Postgres-backed session Store via SQLModel async (test: SQLite/aiosqlite).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel

from fastapi_auth.openid.identity.model import FederatedIdentity


class OpenidSession(SQLModel, table=True):
    """SQLModel table for a stored session (identity JSON + expiry)."""

    sid: str = Field(primary_key=True)
    data: str
    expires_at: float


class PostgresStore:
    """Session Store backed by an async SQLAlchemy engine (Postgres/SQLite)."""

    def __init__(self, engine: Any) -> None:
        """Wrap an existing async SQLAlchemy engine."""
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> PostgresStore:
        """Build a PostgresStore from a database URL, lazily importing SQLAlchemy."""
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "PostgresStore requires the 'postgres' extra: "
                "pip install 'fastapi-auth-openid-federated[postgres]'"
            )
            raise RuntimeError(msg) from err
        return cls(create_async_engine(url))

    async def create_all(self) -> None:
        """Create all tables (used directly in tests; migrations own this in prod)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        async with AsyncSession(self._engine) as s:
            await s.merge(
                OpenidSession(sid=sid, data=identity.model_dump_json(), expires_at=time.time() + ttl)
            )
            await s.commit()

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(OpenidSession, sid)
            if row is None:
                return None
            if row.expires_at < time.time():
                await s.delete(row)
                await s.commit()
                return None
            return FederatedIdentity.model_validate_json(row.data)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(OpenidSession, sid)
            if row is not None:
                await s.delete(row)
                await s.commit()

    async def aclose(self) -> None:
        """Dispose the wrapped engine, releasing its connection pool."""
        await self._engine.dispose()
```

- [ ] **Step 5: Test grün laufen lassen**

Run: `uv run pytest tests/session/test_stores_optional.py -v`
Expected: alle passed. (SQLModel `table=True` registriert die Tabelle global; falls die Test-Collection über mehrere Läufe `OpenidSession` doppelt definiert, ist das hier unkritisch — nur ein Modul definiert sie.)

- [ ] **Step 6: Lint**

Run: `make lint`
Expected: exit 0. (Bei ty-Meckern über SQLAlchemy/SQLModel-Instrumented-Attribute: enge `# ty: ignore[...]`-Kommentare mit Begründung sind erlaubt, wie im SAML-`postgres_store.py`.)

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/session/redis_store.py src/fastapi_auth/openid/session/postgres_store.py tests/session/test_stores_optional.py
git commit -m "feat(session): RedisStore + PostgresStore (session-only, optionale Extras)"
```

---

## Task 6: Factory + OidcRP-Verdrahtung + current_user/optional_user

**Files:**
- Create: `src/fastapi_auth/openid/factory.py`
- Modify: `src/fastapi_auth/openid/rp.py` (Store+Backend bauen; Default-`on_authenticated` etabliert Session; `current_user`/`optional_user`; `aclose` schließt Store)
- Test: `tests/test_factory.py`, `tests/test_router.py` (bestehende Router-Tests: `session_secret` ergänzen)

**Interfaces:**
- Produces:
  - `make_store(settings) -> Store` (memory/redis/postgres; fehlendes Extra → `RuntimeError` mit Install-Hinweis).
  - `make_backend(settings, store) -> SessionBackend` (cookie/jwt).
  - `OidcRP`: neue Attribute `store`, `backend`; Default-`on_authenticated` ruft `backend.establish(identity, response)` und redirectet auf den sicheren `next`; `optional_user()`/`current_user()` FastAPI-Dependencies über `backend.load`; `aclose()` schließt zusätzlich den Store.

- [ ] **Step 1: Failing tests schreiben**

`tests/test_factory.py`:

```python
"""Tests for store/backend selection."""

import pytest

from fastapi_auth.openid.factory import make_backend, make_store
from fastapi_auth.openid.session.cookie import CookieBackend
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.session.store import MemoryStore
from fastapi_auth.openid.settings import OidcSettings

_JWKS = {"keys": []}


def _settings(**over) -> OidcSettings:
    base = dict(entity_id="https://rp.example", base_url="https://rp.example", fed_jwks=_JWKS, session_secret="s" * 32)
    base.update(over)
    return OidcSettings(**base)  # type: ignore[arg-type]


def test_make_store_memory_default():
    assert isinstance(make_store(_settings()), MemoryStore)


def test_make_backend_cookie_default():
    settings = _settings()
    assert isinstance(make_backend(settings, make_store(settings)), CookieBackend)


def test_make_backend_jwt():
    settings = _settings(backend="jwt")
    assert isinstance(make_backend(settings, make_store(settings)), JWTBackend)
```

An `tests/test_router.py`: die `_rp`-Settings um `session_secret` ergänzen, damit der jetzt gebaute CookieBackend gültig ist:

```python
    settings = OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=_priv(op),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
    )
```

(nur die eine `OidcSettings(...)`-Konstruktion in `_rp` erhält `session_secret="s" * 32`; alles andere unverändert. Der bestehende Callback-Test prüft weiterhin, dass `on_authenticated` aufgerufen wird — der Custom-`on_auth` in diesem Test ersetzt die Default-Session-Etablierung, also bleibt er gültig.)

- [ ] **Step 2: Tests rot laufen lassen**

Run: `uv run pytest tests/test_factory.py tests/test_router.py -v`
Expected: FAIL (`ModuleNotFoundError: factory` bzw. TypeError/AttributeError in OidcRP).

- [ ] **Step 3: `factory.py` implementieren**

`src/fastapi_auth/openid/factory.py`:

```python
"""Build the Store and SessionBackend from settings.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.openid.session.base import SessionBackend
from fastapi_auth.openid.session.cookie import CookieBackend
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.session.store import MemoryStore, Store
from fastapi_auth.openid.settings import OidcSettings


def make_store(settings: OidcSettings) -> Store:
    """Construct the configured Store backend."""
    if settings.store == "redis":
        try:
            from fastapi_auth.openid.session.redis_store import RedisStore
        except ModuleNotFoundError as err:
            msg = (
                "RedisStore requires the 'redis' extra: "
                "pip install 'fastapi-auth-openid-federated[redis]'"
            )
            raise RuntimeError(msg) from err
        return RedisStore.from_url(settings.redis_url)
    if settings.store == "postgres":
        try:
            from fastapi_auth.openid.session.postgres_store import PostgresStore
        except ModuleNotFoundError as err:
            msg = (
                "PostgresStore requires the 'postgres' extra: "
                "pip install 'fastapi-auth-openid-federated[postgres]'"
            )
            raise RuntimeError(msg) from err
        return PostgresStore.from_url(settings.db_url)
    return MemoryStore()


def make_backend(settings: OidcSettings, store: Store) -> SessionBackend:
    """Construct the configured SessionBackend."""
    if settings.backend == "jwt":
        return JWTBackend(settings)
    return CookieBackend(settings, store)
```

- [ ] **Step 4: `OidcRP` verdrahten**

In `src/fastapi_auth/openid/rp.py`: Importe ergänzen und im Konstruktor Store+Backend bauen, den Default-`on_authenticated` Session-etablierend machen, und `current_user`/`optional_user` + `aclose`-Store ergänzen.

Importe ergänzen:

```python
from fastapi import Depends, HTTPException, status
from fastapi_auth.openid.factory import make_backend, make_store
```

Im `__init__` NACH `self.settings = settings` (und vor `self.router = build_router(self)`):

```python
        self.store = make_store(settings)
        self.backend = make_backend(settings, self.store)
```

Den Default-`on_authenticated` ersetzen (Session etablieren, dann Redirect):

```python
    async def _default_on_authenticated(
        self, request: Request, identity: FederatedIdentity, next_url: str
    ) -> Response:
        target = is_safe_redirect(next_url, self.settings.allowed_redirect_hosts)
        response = RedirectResponse(target, status_code=303)
        await self.backend.establish(identity, response)
        return response
```

Dependencies + erweitertes `aclose` ergänzen:

```python
    def optional_user(self) -> Callable[[Request], Awaitable[FederatedIdentity | None]]:
        """Dependency returning the FederatedIdentity or None."""

        async def _dep(request: Request) -> FederatedIdentity | None:
            return await self.backend.load(request)

        return _dep

    def current_user(self) -> Callable[[Request], Awaitable[FederatedIdentity]]:
        """Dependency returning the FederatedIdentity or raising 401."""

        async def _dep(request: Request) -> FederatedIdentity:
            identity = await self.backend.load(request)
            if identity is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            return identity

        return _dep
```

Und `aclose` erweitern:

```python
    async def aclose(self) -> None:
        """Close the shared httpx client and the session store."""
        await self.http_client.aclose()
        await self.store.aclose()
```

(`Depends` wird für die Dependencies nicht zwingend im Modul gebraucht, wenn Consumer `Depends(rp.current_user())` selbst schreiben — den ungenutzten `Depends`-Import nur aufnehmen, wenn tatsächlich verwendet; sonst weglassen, um `F401` zu vermeiden.)

- [ ] **Step 5: Tests grün laufen lassen**

Run: `uv run pytest tests/test_factory.py tests/test_router.py -v`
Expected: alle passed.

- [ ] **Step 6: Lint + ganze Suite**

Run: `uv run pytest -q && make lint`
Expected: grün; exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/factory.py src/fastapi_auth/openid/rp.py tests/test_factory.py tests/test_router.py
git commit -m "feat(session): Factory + OidcRP-Verdrahtung (Session etablieren, current_user/optional_user)"
```

---

## Task 7: End-to-End-Session-Flow + Public API

**Files:**
- Modify: `src/fastapi_auth/openid/__init__.py` (Re-Exports: `SessionBackend`, `Store` optional; primär `OidcRP` bleibt Einstieg)
- Test: `tests/test_session_flow.py`

**Interfaces:**
- Produces: keine neue Logik — ein End-to-End-Test, der über den TestClient login → callback (Default-`on_authenticated` etabliert eine Cookie-Session) → geschützte Route mit `Depends(rp.current_user())` durchspielt. Optional: `SessionBackend`/`Store` in `__all__` re-exportieren.

- [ ] **Step 1: Failing test schreiben**

`tests/test_session_flow.py`:

```python
"""End-to-end: federated login establishes a session usable via current_user."""

import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from urllib.parse import parse_qs, urlparse

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture


def _rp(op: OpFixture) -> OidcRP:
    settings = OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        # TestClient speaks http://testserver; a Secure cookie would be dropped
        # by the client jar and never sent to /me. Disable Secure for the test.
        cookie_secure=False,
    )
    return OidcRP(settings, clock=lambda: NOW + 10)


def test_login_establishes_session_and_current_user_reads_it():
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
        # unauthenticated -> 401
        assert client.get("/me").status_code == 401
        # drive login
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
        nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
        router.post(f"{OP_ENTITY}/token").respond(
            200, json={"access_token": "at", "id_token": op.id_token(nonce=nonce), "token_type": "Bearer"}
        )
        cb = client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
        assert cb.status_code == 303
        # the session cookie set on the callback response is now in the client jar
        me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["sub"] == "u1"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/test_session_flow.py -v`
Expected: FAIL, falls die Session-Verdrahtung noch nicht greift — sollte nach Task 6 aber grün sein; dieser Test ist die End-to-End-Absicherung. (Wenn er direkt grün ist: gut, er bestätigt die Integration. TDD-Zweck hier ist die Integrations-Absicherung, nicht ein neues Modul.)

- [ ] **Step 3: Public API optional erweitern**

Falls gewünscht, `src/fastapi_auth/openid/__init__.py` um Session-Typen ergänzen (Einstieg bleibt `OidcRP`). Ersetze den `__all__`-Block/Importe so, dass zusätzlich `SessionBackend` und `Store` re-exportiert werden:

```python
from fastapi_auth.openid.session.base import SessionBackend
from fastapi_auth.openid.session.store import Store
```

und in `__all__` (alphabetisch einsortiert) `"SessionBackend"`, `"Store"` ergänzen. `__version__` bleibt.

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/test_session_flow.py tests/test_public_api.py -v`
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

Expected: pytest alle passed (Plan 1–4); ruff „All checks passed!"; `ty` ohne Fehler; `make lint` exit 0. Doku-Markdown-Churn aus `ruff format .` NICHT committen (nur `src`/`tests`).

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/__init__.py tests/test_session_flow.py
git commit -m "feat(session): End-to-End-Session-Flow + SessionBackend/Store in Public API"
```

---

## Self-Review

**Spec-Abdeckung (Plan 4 vs. Design §5 + Roadmap Plan 4):**
- Session-Settings (Cookie/JWT/Store-Auswahl, jwt-Keys) → Task 1 ✅
- `SessionBackend`-Protocol + `Store`-Protocol + `MemoryStore` (session-only) → Task 2 ✅
- Cookie-Default-Backend (itsdangerous + Store) → Task 3 ✅
- JWT-Opt-in-Backend über **joserfc** (HS*/asymmetrisch, Cookie/Bearer, exp-Pin, attrs-Allowlist) → Task 4 ✅
- Redis/Postgres-Stores (optionale Extras) → Task 5 ✅
- Factory + `OidcRP`-Verdrahtung (Session etablieren via `on_authenticated`-Naht) + `current_user`/`optional_user` → Task 6 ✅
- End-to-End (login→callback→Session→current_user) + Public API → Task 7 ✅

**Bewusst NICHT (dokumentiert):** Logout-Route (Plan 5), Discovery/WAYF (Plan 5), Multi-Worker-`LoginStateStore`, Router-Negativpfad-Tests aus Plan 3. Kein stiller Skip.

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt enthält vollständigen, lauffähigen Code (aus dem bewährten SAML-Package gespiegelt, JWT auf joserfc adaptiert). Ein Umsetzungshinweis (venv-Bestätigung `OctKey.import_key`) ist als verbindlicher Vor-Schritt formuliert.

**Typ-Konsistenz:** `OidcSettings`-Session-Felder (T1) ⇄ `SessionBackend`/`Store` (T2) ⇄ `CookieBackend` (T3) ⇄ `JWTBackend` (T4) ⇄ `RedisStore`/`PostgresStore` (T5) ⇄ `make_store`/`make_backend`/`OidcRP` (T6) ⇄ E2E (T7). Alle Backends erfüllen das `SessionBackend`-Protocol (`establish`/`load`/`revoke`); die optionalen keyword-only `now`-Parameter am `JWTBackend` verletzen das Protocol nicht (Aufrufer rufen ohne `now`). `Store`-Implementierungen (Memory/Redis/Postgres) erfüllen dasselbe session-only Protocol.

**Sicherheits-Selbstprüfung:** Cookies `HttpOnly`/`Secure`/`SameSite=lax`; Cookie-Session-ID itsdangerous-signiert + zeitbegrenzt; JWT genau eine `jwt_alg` gepinnt (Signieren+Verifizieren), via joserfc, `exp` geprüft, symmetrisch ≥32 Bytes erzwungen; kein Hand-JOSE; keine Secrets im Log; `session_secret` bleibt optional in den Settings, aber Cookie/JWT-Backend erzwingen die Präsenz/Stärke bei Konstruktion.

---

## Nächster Meilenstein

- **Plan 5 — Discovery/WAYF + Logout:** feste OP-EntityID (passthrough) + embedded WAYF (OP-Auswahl,
  Jinja2, autoescape) für `/openid/login`; best-effort RP-initiated Logout (`/openid/logout` →
  `SessionBackend.revoke` + optional `end_session_endpoint`). Dabei die aus Plan 3/4 offenen Kleinigkeiten
  (Router-Negativpfad-Tests, `/callback` OP-`error`-Param) mitnehmen.
