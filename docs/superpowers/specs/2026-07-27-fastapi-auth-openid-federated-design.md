# Design-Spec: `fastapi-auth-openid-federated`

- **Datum:** 2026-07-27
- **Status:** Entwurf (zur Umsetzung freigegeben)
- **Distribution (PyPI):** `fastapi-auth-openid-federated`
- **Import:** `from fastapi_auth import openid`
- **Repo:** `github.com/edutap-collective/fastapi-auth-openid-federated`
- **Lizenz:** `Apache-2.0 OR EUPL-1.2` (Dual, Empfänger wählt)

## 1. Ziel & Kontext

Ein wiederverwendbares, öffentliches PyPI-Package, das FastAPI-Services das Login via
**Federated OpenID Connect** ermöglicht — Vertrauen zu OpenID Providern (OPs) wird über
**OpenID Federation 1.0** (<https://openid.net/specs/openid-federation-1_0.html>) hergestellt
statt über manuelle Client-Registrierung oder statisch konfigurierten OP-Trust.

Das Package ist der **Relying Party (RP)**-Zwilling zum SAML-Package
`fastapi-auth-saml-federated` innerhalb der `fastapi_auth`-Familie: gleiches Ziel
(föderiertes Login als FastAPI-Baustein), anderes Protokoll (OIDC + OpenID Federation).

### Nicht-Ziele (v1)

- Kein OpenID Provider (OP), kein Trust Anchor / Intermediate (Autoritäts-Seite).
- Kein Handrollen von JOSE-Krypto (Signaturen über `joserfc`).
- Kein Ersatz für die Attribut-/Claim-Freigabe-Policy des OP.

### Package-Familie (`fastapi_auth`-Namespace, PEP 420)

| Distribution (PyPI)              | Import                            | Rolle                     |
| -------------------------------- | --------------------------------- | ------------------------- |
| `fastapi-auth-saml-federated`    | `from fastapi_auth import saml`   | Federated SAML2 (fertig)  |
| `fastapi-auth-openid-federated`  | `from fastapi_auth import openid` | Federated OIDC (dieses)   |
| `fastapi-auth-wallet-oid4vp`     | `from fastapi_auth import wallet` | Wallet / OID4VP (später)  |

`fastapi_auth/` erhält **kein** `__init__.py` (impliziter PEP-420-Namespace), damit mehrere
Distributionen denselben Namespace teilen. Struktur, Tooling und Lizenz spiegeln
`fastapi-auth-saml-federated`.

## 2. Grundarchitektur & Entscheidungen

| Achse             | Entscheidung                                                                    |
| ----------------- | ------------------------------------------------------------------------------- |
| Rolle             | **Federated RP** (OIDC-Login, Vertrauen via OpenID Federation)                  |
| OIDC-Engine       | **authlib** (Auth-Code+PKCE, Token, ID-Token-Validierung), httpx-async          |
| Federation-Schicht| **eigen, auf `joserfc`** (Entity Statements, Trust-Chain, Metadata Policy)      |
| Session-Layer     | **gespiegelt** vom SAML-Package: Cookie (Default) + JWT (opt-in), self-contained|
| Store             | Memory (Default) · Redis · Postgres (optionale Extras)                          |
| Discovery         | feste OP-EntityID (passthrough) + embedded WAYF (OP-Auswahl)                    |
| Client-Reg.       | **automatic** (Federation-Hallmark); explicit später                            |
| Identitätsmodell  | typisiertes `FederatedIdentity` (OIDC-Claims + eduPerson-via-OIDC) + Escape-Hatch|
| JWT/JOSE          | **`joserfc`** überall (Federation-Statements UND JWT-Session-Backend)           |
| System-Dep        | **keine** (JOSE statt XML → kein `xmlsec1`; schlankeres Image als SAML)         |
| Zuschnitt         | Öffentliches PyPI-Package, semver, Sphinx-Doku, CI                              |

**Leitprinzipien:** klare Grenzen (Federation-Schicht kennt keinen Session-Typ, Session-Layer
kein JWT-Federation-Detail); async-first (`httpx.AsyncClient`, keine sync-Libs); Lesbarkeit
vor Kompaktheit (PEP 20); keine selbstgebaute Krypto.

### Package-Struktur

```text
fastapi_auth/                    # PEP 420 Namespace — KEIN __init__.py
  openid/
    __init__.py                  # Public API: OidcRP, OidcSettings, FederatedIdentity, current_user
    settings.py                  # pydantic-settings (Entity/Keys, Trust Anchors, authority_hints, Session…)
    rp.py                        # OidcRP-Fassade + .router + .mount(app) + current_user/optional_user
    router.py                    # /.well-known/openid-federation, /openid/login, /openid/callback, /openid/logout
    federation/                  # OpenID-Federation-Schicht (eigen, joserfc)
      entity_statement.py        #   Entity Statement JWS build/sign/verify
      entity_configuration.py    #   eigene RP Entity Configuration veröffentlichen
      trust_chain.py             #   resolve_trust_chain(leaf → authority_hints → Trust Anchor) + Validierung
      metadata_policy.py         #   Metadata Policy merge + apply (top-down)
      trust_marks.py             #   Trust-Mark-Prüfung (v1: optional/read-only)
      fetch.py                   #   async .well-known + fetch-Endpoints (httpx.AsyncClient)
    oidcclient/                  # OIDC-Client-Schicht (authlib)
      client.py                  #   Auth-Code+PKCE, Token, ID-Token-Validierung (JWKS aus Trust-Chain)
      registration.py            #   automatic client registration (entity_id als client_id, private_key_jwt)
    identity/
      model.py                   #   FederatedIdentity (Pydantic v2)
      registry.py                #   Claim-Name ↔ Feld (OIDC + eduPerson-via-OIDC)
      mapper.py                  #   Claims (id_token + userinfo) → FederatedIdentity
    session/                     # gespiegelt: base/cookie/jwt(joserfc)/store(memory,redis,postgres)/factory
    redirect.py                  # gespiegelt: is_safe_redirect
    discovery/
      embedded.py                #   WAYF-Renderer (OP-Liste)
    py.typed
docs/                            # Sphinx + MyST (Diataxis)
tests/
compose.yml, Dockerfile, Makefile, pyproject.toml
```

## 3. Trust- & Login-Flow (Kern)

```text
Login:  GET /openid/login?op=<op_entity_id>&next=/app     (Discovery: feste OP-EntityID | WAYF)
  1. resolve_trust_chain(op_entity_id):
       GET {op}/.well-known/openid-federation      → OP Entity Configuration (self-signed JWS)
       authority_hints → für jeden Superior: GET {superior fetch_endpoint}?sub={subordinate}
                          → Subordinate Statement (signiert vom Superior)
       … bis zu einem KONFIGURIERTEN Trust Anchor (Kette endet dort)
       Validierung: jede JWS-Signatur (Leaf-Config gegen eigene fed-jwks; jedes Subordinate
                    Statement gegen die jwks des nächst-höheren Statements; TA gegen konfigurierte TA-jwks)
                    + iat/exp + Cache (TTL ~ exp)
       Metadata Policy (TA→leaf) mergen + auf OP-Metadaten anwenden
       → validierte OP-Metadaten (issuer, authorization/token/userinfo_endpoint, jwks)
  2. automatic client registration: RP nutzt seine entity_id als client_id;
     der OP löst die RP-Trust-Chain + RP-Metadaten aus deren Entity Configuration auf.
  3. Auth-Code+PKCE-Redirect → OP authorization_endpoint
     (client_id=RP-entity_id, PKCE S256, state, nonce, redirect_uri aus RP-Metadaten)

Callback: GET /openid/callback?code=…&state=…
  4. Token-Exchange am token_endpoint (Client-Auth via private_key_jwt mit RP-Fed-Keys)
  5. ID-Token validieren (Signatur gegen OP-JWKS AUS der Trust-Chain; iss/aud/azp/nonce/exp)
     + optional userinfo → Claims
  6. Claims → FederatedIdentity → SessionBackend.establish() → Redirect next (is_safe_redirect)

Well-known: GET /.well-known/openid-federation → signierte RP Entity Configuration
            (metadata.openid_relying_party, jwks (fed keys), authority_hints, iat/exp)
```

## 4. Identität & Claim-Mapping (`identity/`)

Eine kuratierte **Registry** mappt Claim-Namen (aus `id_token` + `userinfo`) auf
`FederatedIdentity`-Felder — analog zur SAML-Registry, damit Consumer beide Packages
einheitlich nutzen.

- **Standard-OIDC:** `sub`, `iss`, `email`(+`email_verified`), `name`, `given_name`,
  `family_name`, `preferred_username`, `locale`, `picture`.
- **eduPerson/SCHAC via OIDC (REFEDS „OIDCre"):** `eduperson_scoped_affiliation`,
  `eduperson_principal_name` (→ `eppn`), `eduperson_assurance`, `eduperson_entitlement`,
  `schac_home_organization`, … → dieselben Zielfelder wie im SAML-`FederatedIdentity`.
- Stabiler Identifier: `sub` (pro OP; pairwise/public) zusammen mit `iss`. `claims: dict`
  als Escape-Hatch; Metadaten (`iss`, `auth_time`, `acr`, `amr`).

## 5. Session-Layer (gespiegelt) — §6-Analog des SAML-Packages

`SessionBackend` (Protocol) mit **Cookie-Default** + **JWT-Opt-in (joserfc)**; `Store`
(`memory | redis | postgres`, Redis/PG optionale Extras, `FederatedIdentity` via
`model_dump_json`); `is_safe_redirect` (lokale Pfade + Allowlist); `mount_path`;
Factory + `OidcRP`-Verdrahtung. Self-contained; eine spätere `fastapi-auth-core`-Extraktion
(geteilt mit SAML) bleibt offen.

## 6. Sicherheit

- **Trust-Chain:** jede JWS-Signatur prüfen; Kette MUSS an einem **konfigurierten Trust Anchor**
  enden (kein Trust ohne Anchor — Analog `trust_anchor_cert` bei SAML). `iat`/`exp` + Clock-Skew;
  Trust-Chain-/Statement-Cache mit TTL (respektiert `exp`).
- **Metadata Policy** deterministisch mergen/anwenden (Spec-Regeln), bevor OP-Metadaten vertraut wird.
- **OIDC:** PKCE (S256), `state` (CSRF), `nonce` (ID-Token-Bindung/Replay); ID-Token-Validierung
  (`iss`=OP, `aud`=RP-client_id, `azp`, `nonce`, `exp`, Signatur gegen **Trust-Chain-JWKS**);
  Client-Auth via **private_key_jwt** (RP-Fed-Keys). Open-Redirect-Guard für `next`.
- **RP-Fed-Keys:** Schutz + Rollover (mehrere Keys in der Entity Configuration). Keine Secrets loggen.
- Trust-Mark-Prüfung optional in v1 (read-only; Enforcement später).

## 7. Teststrategie

**Vorteil ggü. SAML: keine System-Dependency** (JOSE statt XML → kein `xmlsec1`).

- **Unit:** *In-Memory-Testföderation* — Test-Trust-Anchor + Intermediate + Leaf-OP; Entity- und
  Subordinate-Statements mit Test-Keys (`joserfc`) signiert; Federation-HTTP (`.well-known`/fetch)
  via **respx** gemockt. Getestet: Trust-Chain-Auflösung/Validierung, Metadata-Policy, Claim-Mapping.
  OIDC: OP-Endpoints (token/jwks/userinfo) via respx + authlib; ID-Token-Validierung mit Test-Keys.
- **E2E (dokumentiert, manuell):** gegen eine echte OIDC-Federation-Testumgebung
  (z. B. GÉANT/SWAMID-OIDCfed-Pilot). **Offener Punkt:** ob `lmuidp-container` OpenID Federation
  spricht (vermutlich nur klassisches OIDC) — als How-to-Recherche markiert. CI deckt die Logik
  über die In-Memory-Föderation ab.
- **Docker/CI:** gespiegelt (compose Redis/Postgres, GitHub Actions, tox-Matrix) — aber **schlankeres
  Image** (kein libxmlsec1) und einfacherer Build.

## 8. Konfiguration (`settings.py`, pydantic-settings) — Skizze

```text
Entity:    entity_id (RP), base_url, mount_path="/openid"
Fed-Keys:  fed_jwks_file / fed_key_file (+ Rollover), authority_hints[]
Trust:     trust_anchors[] = [{entity_id, jwks_file}]  (out-of-band; Kette MUSS hier enden)
Discovery: mode = 'passthrough' | 'embedded'; fixed_op_entity_id
OIDC:      scopes=["openid","profile","email"], redirect_path="/openid/callback",
           client_auth="private_key_jwt", id_token_signing_alg[]
Session:   backend='cookie'|'jwt', store='memory'|'redis'|'postgres', session_secret,
           cookie_*, jwt_alg (joserfc), jwt_ttl, redis_url, db_url
Security:  allowed_redirect_hosts[], clock_skew, trust_chain_cache_ttl
```

## 9. Packaging / CI / Doku

- `uv`-Stack, `pyproject.toml`, ruff (`E,F,W,B,UP,I,D,S`), `ty` (mypy-Fallback), `pytest` +
  `tox`-Matrix (Py 3.12/3.13/3.14). **Keine System-Dependency.**
- Core-Deps: `fastapi`, `pydantic`, `pydantic-settings`, `authlib`, `joserfc`, `httpx`,
  `itsdangerous`; Extras `redis`, `postgres` (+ `asyncpg`/`sqlmodel`); dev: `respx`, `fakeredis`,
  `aiosqlite`, `pytest`, `ruff`, `ty`.
- **GitHub Actions** spiegeln lokal (ruff + ty + pytest/tox + Docker-Build).
- **Sphinx + MyST** (Diataxis, `plone-doc-style`): Tutorial (Föderations-Login), How-tos
  (Trust Anchor konfigurieren, Fed-Keys, Redis/PG-Store, WAYF, echte OIDCfed-Testföderation),
  Reference (Settings, `FederatedIdentity`, Claim-Registry), Explanation (Trust-Chain/Security-Modell).
- **Lizenz:** `Apache-2.0 OR EUPL-1.2` (Dual-Header; SPDX-Ausdruck).

## 10. v1-Scope (YAGNI) & Roadmap

**v1 — drin:**

- RP Entity Configuration veröffentlichen (`/.well-known/openid-federation`, signiert)
- Trust-Chain-Auflösung + Validierung (bis konfiguriertem Trust Anchor), Metadata-Policy-Anwendung
- **automatic client registration** (entity_id als client_id, private_key_jwt)
- OIDC Auth-Code+PKCE-Login; ID-Token-Validierung via Trust-Chain-JWKS; userinfo
- Claim-Mapping → typisiertes `FederatedIdentity` (+ Registry OIDC/eduPerson-via-OIDC)
- Cookie- (Default) + JWT-Session (joserfc); Store memory/redis/postgres
- Discovery: feste OP-EntityID + embedded WAYF; `mount_path`; Security-Guards
- Docker/CI/Doku

**Später (v1.1+):** explicit client registration, Trust-Mark-Enforcement, OP-/TA-Rollen,
RP-initiated Logout via `end_session_endpoint`, Metadaten-/Trust-Chain-Auto-Refresh, IdP-initiated,
generisches Consumer-Identity-Modell, `fastapi-auth-core`-Extraktion (geteilt mit SAML).

**Roadmap (eigene Meilenstein-Pläne, wie beim SAML-Package):**

- **Plan 1 — Fundament & Identität:** Namespace/Tooling/Dual-Lizenz + `FederatedIdentity` +
  Claim-Registry + Mapper (reine Unit-Tests).
- **Plan 2 — Federation-Entity-Core:** Entity Statements (joserfc), Entity Configuration,
  Trust-Chain-Auflösung + Validierung, Metadata Policy (In-Memory-Testföderation via respx).
- **Plan 3 — OIDC-Login:** authlib-Client (Auth-Code+PKCE, Token, ID-Token-Validierung via
  Trust-Chain-JWKS) + automatic client registration + Router (`/login`, `/callback`, well-known).
- **Plan 4 — Session-Backends:** Cookie/JWT(joserfc) + Memory/Redis/Postgres + Factory (gespiegelt).
- **Plan 5 — Discovery/WAYF + Logout:** feste OP + embedded WAYF; best-effort RP-Logout.
- **Plan 6 — Docker/CI/Doku:** compose (Redis/Postgres), `make test-integration`, GitHub Actions +
  tox, Sphinx/MyST-Doku, How-tos.

## 11. Offene Punkte / Risiken

- **Reife der Bausteine:** OIDC (authlib) ist reif; die **OpenID-Federation-Schicht bauen wir
  selbst** — Aufwand + Sorgfalt bei Trust-Chain-Validierung/Policy (Sicherheits-Kern). Mitigiert durch
  In-Memory-Testföderation + adversariale Tests (falscher Signer, fehlender Anchor, abgelaufene Statements).
- **authlib async:** authlib ist primär sync/Framework-integriert; wir nutzen die httpx-basierten
  Bausteine bzw. kapseln bei Bedarf — im Plan verifizieren (Spike).
- **Metadata Policy** ist subtil (Merge-Regeln, `subset_of`/`one_of`/`value`/`default`/`essential`) —
  eng an der Spec implementieren + testen.
- **Echte OIDCfed-Testföderation** für E2E ist rar; primär In-Memory-Föderation, E2E dokumentiert.
