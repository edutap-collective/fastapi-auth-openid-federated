# Öffentliche API

Der öffentliche Einstiegspunkt des Pakets ist `fastapi_auth.openid`:

```python
from fastapi_auth import openid
```

`openid.__all__` umfasst `FederatedIdentity`, `OidcRP`, `OidcSettings`, `SessionBackend`, `Store`, `__version__`, `map_claims` und `select_identifier`.
`FederatedIdentity`, die Claim-Registry, `map_claims` und `select_identifier` sind auf {doc}`/reference/identity` beschrieben, `OidcSettings` auf {doc}`/reference/settings`.
Diese Seite beschreibt `OidcRP`, die Router-Endpunkte sowie `SessionBackend` und `Store`.

## OidcRP

`OidcRP` (`fastapi_auth.openid.rp.OidcRP`) ist die Composition Root: eine konfigurierte Relying Party, die Föderationsschlüssel, Login-State, Session-Store/-Backend und den FastAPI-Router verdrahtet.

```python
OidcRP(
    settings: OidcSettings,
    *,
    on_authenticated: OnAuthenticated | None = None,
    http_client: httpx.AsyncClient | None = None,
    clock: Callable[[], int] | None = None,
)
```

`settings`
: Die {doc}`/reference/settings`-Instanz dieser RP.

`on_authenticated`
: `Callable[[Request, FederatedIdentity, str], Awaitable[Response]]`.
  Wird nach erfolgreichem Callback aufgerufen (Request, Identität, validiertes `next`-Ziel).
  Default: Session etablieren und auf `next` weiterleiten.

`http_client`
: Ein von außen injizierter `httpx.AsyncClient`; wird dann vom Aufrufer verwaltet (kein eigenes Timeout).
  Ohne Angabe erzeugt `OidcRP` einen eigenen Client mit explizitem Timeout (10 Sekunden für Connect/Read/Write/Pool).

`clock`
: `Callable[[], int]`, liefert die aktuelle Zeit als Unix-Epoch; Default `federation.jose.now_epoch`.
  Dient Tests zum Einfrieren der Zeit.

### Methoden und Attribute

`mount(app: FastAPI, **kwargs) -> None`
: Hängt `self.router` unter `settings.mount_path` in die FastAPI-App ein.
  `**kwargs` werden unverändert an `FastAPI.include_router()` durchgereicht (z. B. `dependencies=[...]`).

`current_user() -> Callable[[Request], Awaitable[FederatedIdentity]]`
: Liefert eine FastAPI-Dependency, die die `FederatedIdentity` aus der Session lädt oder `HTTPException(401)` wirft, wenn keine Session vorliegt.

`optional_user() -> Callable[[Request], Awaitable[FederatedIdentity | None]]`
: Liefert eine FastAPI-Dependency, die die `FederatedIdentity` aus der Session lädt oder `None` zurückgibt.

`identifier(identity: FederatedIdentity) -> str | None`
: Der von dieser RP gewählte stabile Identifier: `select_identifier(identity, "sub", ["eppn", "preferred_username"])`.

`op_choices() -> list[OpChoice]`
: Baut die WAYF-Liste aus `settings.op_list` (Anzeigename fällt auf den Entity-Identifier zurück).

`op_logout_url(identity) -> str | None`
: Best-effort `end_session_endpoint`-URL des OP der Identität, oder `None` (siehe {doc}`/explanation/security-model`).

`aclose() -> None`
: Schließt den geteilten `httpx.AsyncClient` sowie den Session-Store; sollte beim Shutdown der App aufgerufen werden.

`settings`, `fed_key`, `fed_public`, `state_store`, `http_client`, `clock`, `store`, `backend`, `jinja_env`, `on_authenticated`, `router`
: Öffentlich lesbare Attribute (kein führender Unterstrich), damit die Router-Factory ohne Zugriffsverletzung darauf zugreifen kann.

## Router-Endpunkte

`OidcRP.mount(app)` hängt vier Routen unter `settings.mount_path` ein (Default `/openid`).
Die tatsächliche `redirect_uri`, die dem OP gemeldet wird (`settings.callback_url`), sowie der Logout-Pfad (`settings.logout_path`) werden separat konfiguriert und müssen laut Validator mit `mount_path` beginnen; mit den Default-Werten stimmen sie mit den unten aufgeführten Pfaden überein.

| Methode | Pfad (relativ zu `mount_path`) | Beschreibung |
|---|---|---|
| `GET` | `/.well-known/openid-federation` | Liefert die signierte Entity Configuration dieser RP (`application/entity-statement+jwt`). |
| `GET` | `/login` | Startet den Login. Query-Parameter `op` (OP-Entity-ID, im `"passthrough"`-Discovery-Modus) und `next` (Redirect-Ziel nach Login). Im `"embedded"`-Modus ohne `op` wird die WAYF-Seite gerendert. |
| `GET` | `/callback` | Authorization-Code-Callback des OP. Query-Parameter `state`, `code`, optional `error`/`error_description`. |
| `GET` | `/logout` | Beendet die lokale Session und leitet weiter; optional zusätzlich Single Logout am OP (siehe `enable_op_logout`). Query-Parameter `next`. |

## SessionBackend

`SessionBackend` (`fastapi_auth.openid.session.base.SessionBackend`) ist ein `typing.Protocol` für das Etablieren, Laden und Widerrufen einer Login-Session.

```python
class SessionBackend(Protocol):
    async def establish(self, identity: FederatedIdentity, response: Response) -> None: ...
    async def load(self, request: Request) -> FederatedIdentity | None: ...
    async def revoke(self, request: Request, response: Response) -> None: ...
```

Ausgelieferte Implementierungen: `CookieBackend` (serverseitige Session über einen `Store`) und `JWTBackend` (zustandsloses Session-Token).
Welche Implementierung `OidcRP` verwendet, wird über `OidcSettings.backend` gesteuert.

## Store

`Store` (`fastapi_auth.openid.session.store.Store`) ist ein `typing.Protocol` für die Session-Persistenz, die `CookieBackend` verwendet.

```python
class Store(Protocol):
    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None: ...
    async def load_session(self, sid: str) -> FederatedIdentity | None: ...
    async def delete_session(self, sid: str) -> None: ...
    async def aclose(self) -> None: ...
```

Ausgelieferte Implementierungen: `MemoryStore` (Default, nicht persistent), `RedisStore` (`redis`-Extra) und `PostgresStore` (`postgres`-Extra).
Welche Implementierung verwendet wird, steuert `OidcSettings.store`.
