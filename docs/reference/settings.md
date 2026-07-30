# OidcSettings

`OidcSettings` (`fastapi_auth.openid.settings.OidcSettings`) ist die Konfiguration einer `OidcRP`-Instanz.
Sie ist eine `pydantic-settings`-`BaseSettings`-Klasse.
Alle Felder lassen sich per Umgebungsvariable mit dem Präfix `OIDC_` setzen, alternativ über eine `.env`-Datei im Arbeitsverzeichnis.
Unbekannte Umgebungsvariablen mit anderem Präfix werden ignoriert (`extra="ignore"`).

Diese Seite listet jedes Feld mit Typ, Default und Zweck.
Felder ohne Default sind Pflichtfelder.

## Entity und Endpunkte

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `entity_id` | `str` | *(Pflichtfeld)* | Entity-Identifier dieser RP in der OpenID Federation; erscheint als `iss`/`sub` der eigenen Entity Configuration und als `client_id` gegenüber dem OP. |
| `base_url` | `str` | *(Pflichtfeld)* | Öffentlich erreichbare Basis-URL dieser RP, ohne trailing slash; Grundlage für `callback_url`, `well_known_path` und `absolute_url()`. |
| `mount_path` | `str` | `"/openid"` | Pfadpräfix, unter dem `OidcRP.mount()` den Router in die FastAPI-App einhängt. |
| `redirect_path` | `str` | `"/openid/callback"` | Pfad des Callback-Endpunkts; muss mit `mount_path` beginnen (wird per Validator erzwungen). |

## Föderationsschlüssel und Vertrauen

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `fed_jwks` | `dict[str, object]` | *(Pflichtfeld)* | JWKS mit dem privaten Schlüsselmaterial dieser RP; signiert die eigene Entity Configuration, Request Objects und Client Assertions. |
| `authority_hints` | `list[str]` | `[]` | Entity-Identifier der unmittelbaren Superiors dieser RP in der Föderation; erscheinen in der eigenen Entity Configuration. |
| `trust_anchors` | `dict[str, dict[str, object]]` | `{}` | Out-of-band konfigurierte Trust Anchors: Entity-Identifier auf öffentliches JWKS abgebildet. Eine Trust Chain gilt nur als vertrauenswürdig, wenn sie an einem hier konfigurierten Anchor endet. |
| `rp_metadata` | `dict[str, object]` | `{}` | Zusätzliche `openid_relying_party`-Metadaten, die in die eigene Entity Configuration einfließen (z. B. `client_name`). `redirect_uris` und `post_logout_redirect_uris` werden automatisch ergänzt, falls nicht bereits gesetzt. |

## OIDC-Request

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `scopes` | `list[str]` | `["openid", "profile", "email"]` | Angeforderte OAuth-Scopes im Authorization Request. |
| `id_token_signing_alg_values` | `list[str]` | `["RS256", "ES256"]` | Erlaubte Signaturalgorithmen für das ID-Token; wird explizit an die Verifikation übergeben (Algorithmus-Pinning, kein `alg: none`). |
| `fetch_userinfo` | `bool` | `False` | Wenn gesetzt, ruft die RP nach dem Token-Austausch zusätzlich den `userinfo_endpoint` auf und mischt dessen Claims in die Identität. |

## Laufzeiten und Clock Skew (Sekunden)

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `request_object_lifetime` | `int` | `120` | Gültigkeitsdauer (`exp - iat`) des signierten Request Objects. |
| `client_assertion_lifetime` | `int` | `60` | Gültigkeitsdauer der `private_key_jwt`-Client-Assertion beim Token-Austausch. |
| `login_state_ttl` | `int` | `300` | Gültigkeitsdauer eines In-Flight-Login-Vorgangs (State, Nonce, PKCE-Verifier) im `LoginStateStore`. |
| `clock_skew` | `int` | `60` | Erlaubte Zeitabweichung (Leeway) bei der Prüfung von `iat`/`exp` in Trust-Chain-Statements und ID-Token. |

## Sicherheit

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `allowed_redirect_hosts` | `list[str]` | `[]` | Allowlist absoluter Hosts, zu denen `next`-Redirect-Ziele nach Login/Logout zeigen dürfen; verhindert Open Redirects (siehe {doc}`/explanation/security-model`). |

## Discovery

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `discovery_mode` | `Literal["passthrough", "embedded"]` | `"passthrough"` | `"passthrough"`: Der aufrufende Client übergibt den OP direkt per `op`-Query-Parameter. `"embedded"`: Die RP rendert selbst eine WAYF-Auswahlseite (siehe `op_list`). |
| `fixed_op_entity_id` | `str \| None` | `None` | Im `"passthrough"`-Modus verwendeter OP, wenn `/login` ohne `op`-Parameter aufgerufen wird. |
| `op_list` | `list[dict[str, str]]` | `[]` | Statische WAYF-Einträge für `"embedded"`-Discovery, je Eintrag `{"entity_id": ..., "display_name": ...}`. |

## Logout

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `logout_path` | `str` | `"/openid/logout"` | Pfad des Logout-Endpunkts; muss mit `mount_path` beginnen (wird per Validator erzwungen). |
| `post_logout_redirect_uris` | `list[str]` | `[]` | Beim OP registrierte `post_logout_redirect_uri`-Werte; der erste Eintrag wird beim OP-Logout verwendet. |
| `post_logout_default` | `str` | `"/"` | Lokales Redirect-Ziel nach Logout, wenn kein `next`-Parameter übergeben wurde. |
| `enable_op_logout` | `bool` | `False` | Aktiviert best-effort Single Logout am OP (`end_session_endpoint`), zusätzlich zum lokalen Session-Abbau. |

## Session

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `session_cookie_name` | `str` | `"fa_openid_session"` | Name des Session-Cookies. |
| `session_secret` | `str \| None` | `None` | Signaturschlüssel für das Session-Cookie; Pflicht für `backend="cookie"` (Validierung erfolgt beim Aufbau der `CookieBackend`). |
| `session_ttl` | `int` | `28800` | Gültigkeitsdauer einer Session in Sekunden (8 Stunden). |
| `cookie_secure` | `bool` | `True` | Setzt das `Secure`-Attribut auf dem Session-Cookie. |

## Session-Backend und Store-Auswahl

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `backend` | `Literal["cookie", "jwt"]` | `"cookie"` | `"cookie"`: serverseitige Session, adressiert über eine signierte Session-ID im Cookie. `"jwt"`: zustandsloses Session-Token (siehe `jwt_*`-Felder). |
| `store` | `Literal["memory", "redis", "postgres"]` | `"memory"` | Backend für serverseitige Sessions (nur relevant für `backend="cookie"`). `"memory"` ist nicht persistent und nur für Einzelprozess-Deployments geeignet. |
| `redis_url` | `str` | `"redis://localhost:6379/0"` | Verbindungs-URL für `store="redis"`; erfordert das `redis`-Extra. |
| `db_url` | `str` | `"sqlite+aiosqlite:///:memory:"` | SQLAlchemy-Async-URL für `store="postgres"`; erfordert das `postgres`-Extra. |

## JWT-Backend (opt-in, joserfc)

Nur relevant für `backend="jwt"`.

| Feld | Typ | Default | Zweck |
|---|---|---|---|
| `jwt_alg` | `str` | `"HS256"` | Signaturalgorithmus des Session-JWT. Darf nicht `"none"` oder leer sein (wird per Validator abgelehnt). |
| `jwt_ttl` | `int` | `3600` | Gültigkeitsdauer des Session-JWT in Sekunden. |
| `jwt_secret` | `str \| None` | `None` | Gemeinsames Secret für symmetrische Algorithmen (`HS*`); fällt auf `session_secret` zurück, wenn nicht gesetzt (siehe `jwt_signing_secret`). |
| `jwt_jwks` | `dict[str, object] \| None` | `None` | JWKS mit privatem Schlüsselmaterial für asymmetrische Algorithmen (`RS256`, `ES256`, `EdDSA`, ...); signiert mit dem ersten privaten Schlüssel, verifiziert mit dessen öffentlichem Anteil. |
| `jwt_attributes` | `list[str] \| None` | `None` | Wenn gesetzt, werden nur diese `FederatedIdentity`-Feldnamen im `attrs`-Claim des Tokens geführt (Datenminimierung). |

```{important}
Für `backend="jwt"` erzwingt ein Validator starkes Schlüsselmaterial: symmetrische Algorithmen benötigen ein `jwt_secret`/`session_secret` von mindestens 32 Byte, asymmetrische Algorithmen benötigen ein gesetztes `jwt_jwks`.
Ein `OidcSettings`-Objekt mit unzureichendem Schlüsselmaterial lässt sich in diesem Fall nicht konstruieren (`ValueError`).
```

## Berechnete Eigenschaften und Methoden

Diese Werte werden nicht direkt konfiguriert, sondern aus den obigen Feldern abgeleitet.

`callback_url` (Property)
: Absolute `redirect_uri`, die dem OP gemeldet wird: `base_url + redirect_path`.

`well_known_path` (Property)
: Pfad der eigenen Entity Configuration, immer `/.well-known/openid-federation`.

`absolute_url(path)` (Methode)
: Absolute URL für einen Router-Pfad relativ zu `mount_path`: `base_url + mount_path + path`.

`jwt_is_symmetric()` (Methode)
: `True`, wenn `jwt_alg` mit `"HS"` beginnt.

`jwt_signing_secret` (Property)
: `jwt_secret`, falls gesetzt, sonst `session_secret`, sonst der leere String.
