# How-to: Session-Backend und Store wählen

Diese Anleitung zeigt Ihnen, wie Sie zwischen den beiden Session-Backends (`cookie`, `jwt`) und, bei `cookie`, zwischen den drei Stores (`memory`, `redis`, `postgres`) wählen.

## Cookie-Backend mit serverseitigem Store (Standard)

Im Standardfall (`backend="cookie"`) trägt das Cookie nur eine signierte Session-ID; die eigentliche `FederatedIdentity` liegt serverseitig im konfigurierten `Store` (siehe {doc}`/explanation/security-model`).
Welcher Store das ist, steuert `OidcSettings.store`:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    session_secret=session_secret,
    backend="cookie",
    store="memory",
)
```

`store="memory"` (Standard) hält Sessions nur im Prozessspeicher.
Verwenden Sie ihn für lokale Entwicklung und Einzelprozess-Deployments; er verliert alle Sessions bei jedem Neustart und funktioniert nicht über mehrere Worker-Prozesse hinweg.

### Redis als Store

Für mehrere Worker-Prozesse oder persistente Sessions wählen Sie `store="redis"`:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    session_secret=session_secret,
    backend="cookie",
    store="redis",
    redis_url="redis://localhost:6379/0",
)
```

`RedisStore` benötigt das `redis`-Extra:

```shell
uv pip install "fastapi-auth-openid-federated[redis]"
```

Ohne installiertes Extra bricht `OidcRP(settings)` beim Start mit einer `RuntimeError` ab, die auf das fehlende Extra hinweist.

### Postgres als Store

Für einen relationalen Store wählen Sie `store="postgres"`:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    session_secret=session_secret,
    backend="cookie",
    store="postgres",
    db_url="postgresql+asyncpg://user:pw@localhost:5432/mydb",
)
```

`PostgresStore` benötigt das `postgres`-Extra:

```shell
uv pip install "fastapi-auth-openid-federated[postgres]"
```

`PostgresStore` legt sein Schema nicht automatisch an.
Rufen Sie `create_all()` einmalig beim Anwendungsstart auf, zum Beispiel im FastAPI-`lifespan`:

```python
from fastapi_auth.openid.session.postgres_store import PostgresStore

store = PostgresStore.from_url(settings.db_url)
await store.create_all()
```

```{note}
`create_all()` ist für Entwicklung und Tests gedacht.
Verwalten Sie das Schema in einem produktiven Deployment stattdessen über ein Migrationswerkzeug Ihrer Wahl.
```

## JWT-Backend (zustandslos)

Mit `backend="jwt"` entfällt der serverseitige Store vollständig: Die Identität steckt signiert im Session-Token selbst, das als Cookie oder `Authorization: Bearer`-Header gelesen wird.

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    backend="jwt",
    jwt_alg="HS256",
    jwt_secret="a-shared-secret-of-at-least-32-bytes!!",
)
```

Ein Validator erzwingt starkes Schlüsselmaterial: Bei einem symmetrischen Algorithmus (`HS*`) müssen `jwt_secret` (oder ersatzweise `session_secret`) mindestens 32 Byte lang sein; bei einem asymmetrischen Algorithmus (`RS256`, `ES256`, `EdDSA`, ...) ist stattdessen `jwt_jwks` mit einem privaten Schlüssel Pflicht.
Ohne ausreichendes Schlüsselmaterial lässt sich das `OidcSettings`-Objekt für `backend="jwt"` nicht konstruieren.

Wenn Sie nicht alle `FederatedIdentity`-Felder im Token führen wollen, schränken Sie sie mit `jwt_attributes` ein:

```python
settings = openid.OidcSettings(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=fed_jwks,
    backend="jwt",
    jwt_alg="HS256",
    jwt_secret="a-shared-secret-of-at-least-32-bytes!!",
    jwt_attributes=["sub", "eppn", "display_name"],
)
```

```{seealso}
Alle Felder mit Typ und Default: {doc}`/reference/settings`.
Warum das Cookie-Backend zusätzlich `httponly`/`samesite`/`secure` setzt: {doc}`/explanation/security-model`.
```
