# Plan 2 — Federation-Entity-Core (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die sicherheitskritische OpenID-Federation-1.0-Vertrauensschicht bauen: signierte Entity
Statements (joserfc), die eigene RP Entity Configuration, Trust-Chain-Auflösung **und** -Validierung
(bis zu einem konfigurierten Trust Anchor) sowie Metadata-Policy-Merge/-Anwendung — alles gegen eine
In-Memory-Testföderation (respx) adversarial getestet.

**Architecture:** Eigene Federation-Schicht auf `joserfc` (keine reife async-OIDF-Lib). Reine,
seiteneffektfreie Bausteine (Statement-Build/-Verify, Policy-Merge/-Apply) getrennt von der
async-HTTP-Schicht (`fetch.py` mit `httpx.AsyncClient`). Der Trust-Chain-Validator implementiert die
Spec-Regel „ES[j] wird mit einem Key aus ES[j+1].jwks verifiziert; das oberste (vom Trust Anchor
signierte) Statement mit den **out-of-band konfigurierten** TA-Keys" exakt. Metadata-Policy folgt der
festen Operator-Reihenfolge und den Merge-/Apply-Fehlerbedingungen der Spec.

**Tech Stack:** Python 3.12+, joserfc 1.7+ (JWS/JWT/JWK), httpx (async), Pydantic v2, pytest +
pytest-asyncio, respx (HTTP-Mocking), ruff, ty, uv.

## Global Constraints

- Distribution (PyPI): `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header (`SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2`) in **jeder** Quellcodedatei unter `src/`.
- Python-Floor: `>=3.12`. async-first: HTTP über `httpx.AsyncClient`; keine blockierenden Netz-Calls.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung.
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren. `make lint` (scoped `src tests`) MUSS exit 0.
- **Sicherheits-Kern:** Jede JWS-Signatur wird geprüft; Algorithmen werden **explizit gepinnt** (`algorithms=[...]`, nie `none`); die Trust Chain MUSS an einem **konfigurierten** Trust Anchor enden (kein Trust ohne Anchor); `iat`/`exp` werden mit Clock-Skew geprüft; unverifiziertes „Peeken" eines Headers/Payloads dient NUR der Routing-Entscheidung (welchen Key/Endpoint laden) und wird nie vertraut, bevor `jwt.decode` die Signatur bestätigt hat.
- Keine Secrets loggen. Private Keys nie serialisieren außer in vom Aufrufer explizit gewünschten Kontexten.
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).
- Commits auf `main` sind für dieses neue Repo ausdrücklich erlaubt (greenfield, vom Nutzer so gewünscht). **Niemals `git push`.**

### Bewusst NICHT in Plan 2 (YAGNI / Folgepläne)

- **Trust Marks** (Spec §5): v1 read-only/optional — kommt bei Bedarf später; hier nicht gebaut.
- **Constraints-Enforcement** (Spec §6.2, `naming_constraints`, `max_path_length`, `allowed_entity_types`): auf v1.1 verschoben; Plan 2 setzt keine Constraints durch (dokumentierter Verzicht, nicht stiller Skip).
- **Explicit Client Registration** (Spec §12): nicht Teil dieses Meilensteins.
- **OIDC-Login / authlib / Router / Settings-Verdrahtung:** Plan 3. Alle Bausteine hier sind reine Funktionen mit explizit übergebenen Parametern (keine `settings.py`-Kopplung).

## Verifizierte Fakten (Recherche — verbindlich für die Implementierung)

**joserfc 1.7.4** (Docs: <https://jose.authlib.org/>):

- Keys: `from joserfc.jwk import RSAKey, ECKey, KeySet`. `RSAKey.generate_key(key_size=2048, parameters={"kid": ...}, private=True)`, `ECKey.generate_key(crv="P-256", parameters={"kid": ...})`. `key.kid`, `key.as_dict(private=False)` (public-only). `KeySet([k1, k2])`, `KeySet.import_key_set({"keys":[...]})`, `keyset.as_dict(private=False)` → `{"keys":[...]}`, `keyset.get_by_kid(kid)`.
- Signieren: `from joserfc import jwt`; `jwt.encode(header: dict, claims: dict, key, algorithms=[alg]) -> str`. Der `header`-Dict wird **verbatim** als Protected Header genutzt (nichts wird automatisch injiziert).
- Verifizieren (nur Signatur!): `jwt.decode(token: str, key_or_keyset, algorithms=[...]) -> Token` mit `.header`, `.claims`. Bei `KeySet` wird der Key automatisch per `kid` aus dem Header gewählt. Fehler: `from joserfc.errors import BadSignatureError, InvalidKeyIdError` (falscher/kein Key).
- **`jwt.decode` prüft KEINE `exp`/`iat`.** Zeit-/Claim-Prüfung ist ein separater Schritt — wir prüfen `iat`/`exp` explizit (transparenter als `JWTClaimsRegistry`).
- Header/Payload unverifiziert lesen: Für `iss`/`authority_hints`/`kid` während der Auflösung base64url-dekodieren wir das Payload-Segment selbst (deterministisch, explizit als „unverified" markiert).

**OpenID Federation 1.0 (Final, 2026-02-17)** — Kernregeln (Section-Zitate in den Docstrings der Module):

- `typ`-Header **immer** `entity-statement+jwt` (EC und Subordinate Statement gleich). Unterscheidung: EC ⇔ `iss == sub`; Subordinate Statement ⇔ `iss != sub`. `kid`-Header REQUIRED, `alg != none`.
- Required Claims (beide): `iss, sub, iat, exp, jwks`. EC zusätzlich `authority_hints` (REQUIRED, wenn Superior existiert; MUST NOT bei TA ohne Superior); Subordinate Statement zusätzlich optional `metadata`, `metadata_policy`, `constraints` (und MUST NOT `authority_hints`).
- `jwks` enthält **immer die Keys des Subjects (`sub`)**.
- Well-known-Pfad (§9): `entity_id` ohne trailing `/`, dann `"/.well-known/openid-federation"` **anhängen** (Suffix-Konkatenation, auch bei Pfad-Anteil). Content-Type `application/entity-statement+jwt`.
- Fetch-Endpoint (§8.1): aus der EC des Superiors `metadata.federation_entity.federation_fetch_endpoint`. Request: HTTP GET, **genau ein** Query-Param `sub=<subject-entity-id>`. (Kein `iss`-Param.) Content-Type `application/entity-statement+jwt`.
- Chain-Repräsentation (§4): `[ES[0]=Leaf-EC (self-signed), ES[1..n-1]=Subordinate Statements …]`, Leaf zuerst; die TA-EC selbst MAY fehlen (wir nutzen konfigurierte TA-Keys).
- Signaturkette (§4/§10.2): `ES[0]` self-signed mit Key aus `ES[0].jwks`; für `j=0..n-2` wird `ES[j]` mit einem Key aus `ES[j+1].jwks` verifiziert; das **oberste** Statement `ES[n-1]` (Issuer = TA) wird mit den **konfigurierten** TA-Keys verifiziert. Linkage: `ES[j].iss == ES[j+1].sub`. Chain-`exp` = `min(exp)` über alle Statements.
- Metadata-Policy (§6.1): Operatoren `value, add, default, one_of, subset_of, superset_of, essential`; Anwendungs-Reihenfolge fest **`value → add → default → one_of → subset_of → superset_of → essential`**. Merge über die Kette **TA→Leaf** (most-superior zuerst). Merge-Konflikte (`value≠value`, `default≠default`, leere `one_of`-Intersection, unerlaubte Operator-Kombination, unbekannter `metadata_policy_crit`-Operator) ⇒ Policy-Error ⇒ Chain invalid. Apply-Fehler (`essential` fehlt, `one_of`/`subset_of`/`superset_of` verletzt, resultierender `null`) ⇒ Metadata „broken" ⇒ Chain invalid.

## File Structure

```text
pyproject.toml                                        # joserfc + httpx in Core-Deps, respx in dev
src/fastapi_auth/openid/federation/__init__.py        # Public API der Federation-Schicht
src/fastapi_auth/openid/federation/errors.py          # FederationError-Hierarchie
src/fastapi_auth/openid/federation/jose.py            # JOSE-Primitive: load/public-KeySet, sign, verify, peek, time
src/fastapi_auth/openid/federation/entity_statement.py# Build + Verify von Entity Statements
src/fastapi_auth/openid/federation/entity_configuration.py # eigene RP Entity Configuration bauen/signieren
src/fastapi_auth/openid/federation/fetch.py           # async .well-known / fetch-endpoint (httpx)
src/fastapi_auth/openid/federation/metadata_policy.py # merge + apply (Operator-Semantik)
src/fastapi_auth/openid/federation/trust_chain.py     # resolve + validate + resolve_and_validate (+ Cache)
tests/federation/__init__.py
tests/federation/conftest.py                          # In-Memory-Testföderation (Keys, Statements, respx)
tests/federation/test_jose.py
tests/federation/test_entity_statement.py
tests/federation/test_entity_configuration.py
tests/federation/test_fetch.py
tests/federation/test_trust_chain_resolve.py
tests/federation/test_trust_chain_validate.py
tests/federation/test_metadata_policy.py
tests/federation/test_resolve_and_validate.py
```

---

## Task 1: joserfc-Dependency + JOSE-Primitive + Fehlerhierarchie

**Files:**
- Modify: `pyproject.toml` (Core-Deps `joserfc`, `httpx`; `respx` bleibt dev)
- Create: `src/fastapi_auth/openid/federation/__init__.py`, `src/fastapi_auth/openid/federation/errors.py`, `src/fastapi_auth/openid/federation/jose.py`
- Create: `tests/federation/__init__.py`, `tests/federation/test_jose.py`

**Interfaces:**
- Consumes: nichts aus früheren Tasks.
- Produces (aus `federation.jose`):
  - `DEFAULT_SIGNING_ALGORITHMS: tuple[str, ...]`
  - `ENTITY_STATEMENT_TYP = "entity-statement+jwt"`
  - `load_keyset(jwks: dict[str, object]) -> KeySet`
  - `public_jwks(keyset: KeySet) -> dict[str, object]`
  - `signing_alg(key: Key) -> str`
  - `sign_entity_statement(claims: dict[str, object], key: Key) -> str`
  - `verify_signature(token: str, key: KeySet | Key, *, algorithms: Sequence[str]) -> dict[str, object]` (nur Signatur; wirft `SignatureError`)
  - `peek_claims(token: str) -> dict[str, object]` (UNVERIFIED)
  - `now_epoch() -> int`
- Produces (aus `federation.errors`): `FederationError`, `EntityStatementError`, `SignatureError`, `TrustChainError`, `MetadataPolicyError`, `FetchError`.

- [ ] **Step 1: `joserfc` + `httpx` in Core-Deps aufnehmen**

In `pyproject.toml` den `dependencies`-Block ersetzen durch:

```toml
dependencies = [
    "fastapi>=0.115",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "joserfc>=1.7",
    "httpx>=0.27",
]
```

`respx` und `httpx` bleiben zusätzlich in `[project.optional-dependencies].dev` (httpx-Doppelnennung ist harmlos; dev braucht keine Änderung, respx ist bereits dort). Dann installieren:

Run: `uv pip install -U -e ".[dev]"`
Expected: joserfc + httpx sind installiert (`uv run python -c "import joserfc, httpx; print(joserfc.__version__)"` → `1.7.x`).

- [ ] **Step 2: Failing test schreiben**

`tests/federation/__init__.py`: leere Datei anlegen (`touch`).

`tests/federation/test_jose.py`:

```python
"""Tests for the low-level JOSE primitives used by the federation layer."""

import pytest
from joserfc.jwk import ECKey, KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import SignatureError


def _rsa(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_signing_alg_rsa_and_ec():
    assert jose.signing_alg(_rsa("a")) == "RS256"
    assert jose.signing_alg(ECKey.generate_key(crv="P-256", parameters={"kid": "e"})) == "ES256"


def test_public_jwks_strips_private_material():
    ks = KeySet([_rsa("k1")])
    pub = jose.public_jwks(ks)
    assert pub["keys"][0]["kid"] == "k1"
    assert "d" not in pub["keys"][0]  # no private exponent


def test_sign_uses_entity_statement_typ_and_kid():
    key = _rsa("signer-1")
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, key)
    peeked_header = jose.peek_header(token)
    assert peeked_header["typ"] == jose.ENTITY_STATEMENT_TYP
    assert peeked_header["kid"] == "signer-1"
    assert peeked_header["alg"] == "RS256"


def test_sign_and_verify_roundtrip_via_keyset():
    key = _rsa("signer-2")
    token = jose.sign_entity_statement({"iss": "x", "sub": "x", "n": 1}, key)
    keyset = KeySet([_rsa("other"), key])  # signer not first -> kid selection must work
    claims = jose.verify_signature(token, keyset, algorithms=["RS256"])
    assert claims["n"] == 1


def test_verify_wrong_key_raises_signature_error():
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, _rsa("signer-3"))
    with pytest.raises(SignatureError):
        jose.verify_signature(token, KeySet([_rsa("attacker")]), algorithms=["RS256"])


def test_verify_unknown_kid_raises_signature_error():
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, _rsa("known"))
    with pytest.raises(SignatureError):
        jose.verify_signature(token, KeySet([_rsa("nope")]), algorithms=["RS256"])


def test_peek_claims_is_unverified_read():
    token = jose.sign_entity_statement({"iss": "leaf", "authority_hints": ["ta"]}, _rsa("k"))
    peeked = jose.peek_claims(token)
    assert peeked["iss"] == "leaf"
    assert peeked["authority_hints"] == ["ta"]
```

- [ ] **Step 3: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_jose.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.openid.federation`).

- [ ] **Step 4: Fehlerhierarchie implementieren**

`src/fastapi_auth/openid/federation/__init__.py`:

```python
"""OpenID Federation 1.0 trust layer (entity statements, trust chains, metadata policy).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/openid/federation/errors.py`:

```python
"""Exception hierarchy for the federation layer.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class FederationError(Exception):
    """Base class for all federation-layer failures."""


class EntityStatementError(FederationError):
    """An entity statement is malformed, mistyped, or fails structural checks."""


class SignatureError(FederationError):
    """A JWS signature could not be verified (bad signature or no matching key)."""


class TrustChainError(FederationError):
    """A trust chain could not be resolved or validated up to a configured anchor."""


class MetadataPolicyError(FederationError):
    """A metadata policy is invalid, conflicts on merge, or fails on application."""


class FetchError(FederationError):
    """Fetching an entity configuration or subordinate statement failed."""
```

- [ ] **Step 5: JOSE-Primitive implementieren**

`src/fastapi_auth/openid/federation/jose.py`:

```python
"""Low-level JOSE helpers for OpenID Federation entity statements.

All entity statements are signed JWTs with an explicit ``typ`` of
``entity-statement+jwt`` (OpenID Federation 1.0, Section 3). Signature
verification here is deliberately *signature-only*; time/claim validation is a
separate, explicit step (see ``entity_statement`` / ``trust_chain``), because
``joserfc.jwt.decode`` does not check ``exp``/``iat``.

``peek_*`` reads an unverified token header/payload — used ONLY to decide which
key or endpoint to fetch during trust-chain resolution. Never trust its output
before ``verify_signature`` has confirmed the signature.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Sequence

from joserfc import jwt
from joserfc.errors import BadSignatureError, InvalidKeyIdError
from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.federation.errors import SignatureError

ENTITY_STATEMENT_TYP = "entity-statement+jwt"

#: Algorithms we are willing to accept/produce. ``none`` is never allowed.
DEFAULT_SIGNING_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "PS256",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)

_EC_CRV_TO_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


def now_epoch() -> int:
    """Return the current time as integer seconds since the epoch."""
    return int(time.time())


def load_keyset(jwks: dict[str, object]) -> KeySet:
    """Import a public/private JWKS dict (``{"keys": [...]}``) into a KeySet."""
    return KeySet.import_key_set(jwks)


def public_jwks(keyset: KeySet) -> dict[str, object]:
    """Export a KeySet to a public-only JWKS dict suitable for publishing."""
    return keyset.as_dict(private=False)


def signing_alg(key: Key) -> str:
    """Pick the JWS ``alg`` for a signing key from its type/curve."""
    material = key.as_dict(private=False)
    kty = material["kty"]
    if kty == "RSA":
        return "RS256"
    if kty == "EC":
        crv = str(material.get("crv", ""))
        alg = _EC_CRV_TO_ALG.get(crv)
        if alg is None:
            raise SignatureError(f"unsupported EC curve: {crv!r}")
        return alg
    if kty == "OKP":
        return "EdDSA"
    raise SignatureError(f"unsupported key type: {kty!r}")


def sign_entity_statement(claims: dict[str, object], key: Key) -> str:
    """Sign a claims dict as an ``entity-statement+jwt`` compact JWS."""
    alg = signing_alg(key)
    header = {"alg": alg, "typ": ENTITY_STATEMENT_TYP, "kid": key.kid}
    return jwt.encode(header, claims, key, algorithms=[alg])


def verify_signature(
    token: str,
    key: KeySet | Key,
    *,
    algorithms: Sequence[str],
) -> dict[str, object]:
    """Verify the JWS signature only and return the claims.

    Raises ``SignatureError`` on a bad signature or when no key in a KeySet
    matches the token's ``kid``. Does NOT validate ``exp``/``iat``.
    """
    try:
        result = jwt.decode(token, key, algorithms=list(algorithms))
    except (BadSignatureError, InvalidKeyIdError) as exc:
        raise SignatureError(str(exc)) from exc
    return dict(result.claims)


def _b64url_segment(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def peek_header(token: str) -> dict[str, object]:
    """Return the UNVERIFIED protected header (for routing decisions only)."""
    header_segment = token.split(".", 2)[0]
    return json.loads(_b64url_segment(header_segment))


def peek_claims(token: str) -> dict[str, object]:
    """Return the UNVERIFIED payload claims (for routing decisions only)."""
    payload_segment = token.split(".", 2)[1]
    return json.loads(_b64url_segment(payload_segment))
```

- [ ] **Step 6: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_jose.py -v`
Expected: alle passed.

- [ ] **Step 7: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml src/fastapi_auth/openid/federation tests/federation/__init__.py tests/federation/test_jose.py
git commit -m "feat(federation): JOSE-Primitive (joserfc) + Fehlerhierarchie"
```

---

## Task 2: Entity Statement — Build + Verify

**Files:**
- Create: `src/fastapi_auth/openid/federation/entity_statement.py`
- Test: `tests/federation/test_entity_statement.py`

**Interfaces:**
- Consumes: `jose.*` (Task 1), `errors.*` (Task 1).
- Produces:
  - `REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "sub", "iat", "exp", "jwks")`
  - `build_entity_configuration(*, entity_id, jwks, authority_hints=None, metadata=None, lifetime=3600, now=None) -> dict`
  - `build_subordinate_statement(*, issuer, subject, jwks, metadata=None, metadata_policy=None, constraints=None, lifetime=3600, now=None) -> dict`
  - `is_entity_configuration(claims: dict) -> bool` (`iss == sub`)
  - `verify_statement(token, keyset, *, algorithms=DEFAULT_SIGNING_ALGORITHMS, leeway=0, now=None) -> dict` — Signatur **und** Struktur (`typ`, Required Claims) **und** Zeit (`iat`/`exp` mit Skew). Wirft `EntityStatementError`/`SignatureError`.
  - `check_time(claims, *, leeway=0, now=None) -> None` — `iat`≤now+leeway, `exp`≥now−leeway; sonst `EntityStatementError`.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_entity_statement.py`:

```python
"""Tests for building and verifying entity statements."""

import pytest
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import EntityStatementError, SignatureError

NOW = 1_700_000_000


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def _pub(key: RSAKey) -> dict:
    return jose.public_jwks(KeySet([key]))


def test_entity_configuration_is_self_issued_with_hints():
    key = _key("leaf")
    claims = es.build_entity_configuration(
        entity_id="https://leaf.example",
        jwks=_pub(key),
        authority_hints=["https://ta.example"],
        metadata={"openid_relying_party": {"client_name": "x"}},
        now=NOW,
    )
    assert claims["iss"] == claims["sub"] == "https://leaf.example"
    assert claims["authority_hints"] == ["https://ta.example"]
    assert claims["iat"] == NOW
    assert claims["exp"] == NOW + 3600
    assert es.is_entity_configuration(claims) is True


def test_subordinate_statement_is_not_self_issued_and_has_no_hints():
    key = _key("sub-key")
    claims = es.build_subordinate_statement(
        issuer="https://ta.example",
        subject="https://leaf.example",
        jwks=_pub(key),
        metadata_policy={"openid_provider": {"subject_types_supported": {"value": ["pairwise"]}}},
        now=NOW,
    )
    assert claims["iss"] == "https://ta.example"
    assert claims["sub"] == "https://leaf.example"
    assert "authority_hints" not in claims
    assert "metadata_policy" in claims
    assert es.is_entity_configuration(claims) is False


def test_verify_statement_roundtrip():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    claims = es.verify_statement(token, KeySet([key]), leeway=0, now=NOW + 10)
    assert claims["sub"] == "https://leaf.example"


def test_verify_statement_rejects_expired():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(
            entity_id="https://leaf.example", jwks=_pub(key), lifetime=100, now=NOW
        ),
        key,
    )
    with pytest.raises(EntityStatementError, match="expired"):
        es.verify_statement(token, KeySet([key]), leeway=0, now=NOW + 1000)


def test_verify_statement_rejects_future_iat():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    with pytest.raises(EntityStatementError, match="future"):
        es.verify_statement(token, KeySet([key]), leeway=0, now=NOW - 1000)


def test_verify_statement_rejects_bad_signature():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    with pytest.raises(SignatureError):
        es.verify_statement(token, KeySet([_key("attacker")]), now=NOW + 10)


def test_verify_statement_rejects_wrong_typ():
    from joserfc import jwt

    key = _key("leaf")
    claims = es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW)
    token = jwt.encode({"alg": "RS256", "typ": "JWT", "kid": "leaf"}, claims, key, algorithms=["RS256"])
    with pytest.raises(EntityStatementError, match="typ"):
        es.verify_statement(token, KeySet([key]), now=NOW + 10)


def test_verify_statement_rejects_missing_required_claim():
    key = _key("leaf")
    # Missing "jwks" -> structural failure.
    token = jose.sign_entity_statement(
        {"iss": "https://leaf.example", "sub": "https://leaf.example", "iat": NOW, "exp": NOW + 10},
        key,
    )
    with pytest.raises(EntityStatementError, match="jwks"):
        es.verify_statement(token, KeySet([key]), now=NOW + 1)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_entity_statement.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/federation/entity_statement.py`:

```python
"""Build and verify OpenID Federation entity statements.

An entity statement is a signed JWT with ``typ`` = ``entity-statement+jwt``
(Section 3). When ``iss == sub`` it is a self-issued Entity Configuration;
otherwise it is a Subordinate Statement issued by a superior about its
subordinate. The ``jwks`` claim always carries the *subject's* federation keys.

Verification here combines three checks that the spec keeps distinct:
signature (via ``jose.verify_signature``), structural typing (``typ`` +
required claims), and freshness (``iat``/``exp`` with clock skew). ``joserfc``
does none of the latter two automatically.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import EntityStatementError

REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "sub", "iat", "exp", "jwks")


def build_entity_configuration(
    *,
    entity_id: str,
    jwks: dict[str, object],
    authority_hints: Sequence[str] | None = None,
    metadata: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> dict[str, object]:
    """Build the claims of a self-issued Entity Configuration (``iss == sub``)."""
    issued = jose.now_epoch() if now is None else now
    claims: dict[str, object] = {
        "iss": entity_id,
        "sub": entity_id,
        "iat": issued,
        "exp": issued + lifetime,
        "jwks": jwks,
    }
    if authority_hints is not None:
        claims["authority_hints"] = list(authority_hints)
    if metadata is not None:
        claims["metadata"] = metadata
    return claims


def build_subordinate_statement(
    *,
    issuer: str,
    subject: str,
    jwks: dict[str, object],
    metadata: dict[str, object] | None = None,
    metadata_policy: dict[str, object] | None = None,
    constraints: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> dict[str, object]:
    """Build the claims of a Subordinate Statement (``iss != sub``, no hints)."""
    issued = jose.now_epoch() if now is None else now
    claims: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "iat": issued,
        "exp": issued + lifetime,
        "jwks": jwks,
    }
    if metadata is not None:
        claims["metadata"] = metadata
    if metadata_policy is not None:
        claims["metadata_policy"] = metadata_policy
    if constraints is not None:
        claims["constraints"] = constraints
    return claims


def is_entity_configuration(claims: dict[str, object]) -> bool:
    """True when the statement is self-issued (Entity Configuration)."""
    return claims.get("iss") == claims.get("sub")


def check_structure(claims: dict[str, object]) -> None:
    """Ensure all REQUIRED entity-statement claims are present."""
    for name in REQUIRED_CLAIMS:
        if name not in claims:
            raise EntityStatementError(f"entity statement missing required claim: {name!r}")


def check_time(claims: dict[str, object], *, leeway: int = 0, now: int | None = None) -> None:
    """Validate ``iat`` (not in the future) and ``exp`` (not past), with skew."""
    moment = jose.now_epoch() if now is None else now
    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise EntityStatementError("entity statement has non-integer iat/exp")
    if iat > moment + leeway:
        raise EntityStatementError("entity statement iat is in the future")
    if exp < moment - leeway:
        raise EntityStatementError("entity statement is expired")


def verify_statement(
    token: str,
    keyset: KeySet | Key,
    *,
    algorithms: Sequence[str] = jose.DEFAULT_SIGNING_ALGORITHMS,
    leeway: int = 0,
    now: int | None = None,
) -> dict[str, object]:
    """Verify signature, ``typ``, required claims and freshness of a statement."""
    header = jose.peek_header(token)
    if header.get("typ") != jose.ENTITY_STATEMENT_TYP:
        raise EntityStatementError(
            f"entity statement has wrong typ: {header.get('typ')!r}"
        )
    claims = jose.verify_signature(token, keyset, algorithms=algorithms)
    check_structure(claims)
    check_time(claims, leeway=leeway, now=now)
    return claims
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_entity_statement.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/federation/entity_statement.py tests/federation/test_entity_statement.py
git commit -m "feat(federation): Entity Statement Build + Verify (Signatur/typ/Zeit)"
```

---

## Task 3: Eigene RP Entity Configuration

**Files:**
- Create: `src/fastapi_auth/openid/federation/entity_configuration.py`
- Test: `tests/federation/test_entity_configuration.py`

**Interfaces:**
- Consumes: `jose.*`, `entity_statement.*` (Tasks 1–2).
- Produces:
  - `build_rp_entity_configuration(*, entity_id, fed_jwks_public, authority_hints, rp_metadata, federation_metadata=None, lifetime=3600, now=None) -> dict` — Claims der eigenen RP-EC: `metadata.openid_relying_party = rp_metadata`, optional `metadata.federation_entity`, `jwks = fed_jwks_public`.
  - `sign_rp_entity_configuration(*, entity_id, fed_jwks_public, fed_signing_key, authority_hints, rp_metadata, federation_metadata=None, lifetime=3600, now=None) -> str` — baut + signiert; das Ergebnis ist der Body für `/.well-known/openid-federation`.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_entity_configuration.py`:

```python
"""Tests for publishing the RP's own entity configuration."""

from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_configuration as ec
from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import jose

NOW = 1_700_000_000


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_build_rp_entity_configuration_shape():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    claims = ec.build_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        authority_hints=["https://ta.example"],
        rp_metadata={"client_name": "My RP", "redirect_uris": ["https://rp.example/openid/callback"]},
        now=NOW,
    )
    assert claims["iss"] == claims["sub"] == "https://rp.example"
    assert claims["authority_hints"] == ["https://ta.example"]
    assert claims["jwks"] == pub
    assert claims["metadata"]["openid_relying_party"]["client_name"] == "My RP"


def test_signed_rp_entity_configuration_verifies_against_own_jwks():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    token = ec.sign_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        fed_signing_key=key,
        authority_hints=["https://ta.example"],
        rp_metadata={"client_name": "My RP"},
        now=NOW,
    )
    # Self-signed: verifiable with the jwks it publishes.
    claims = es.verify_statement(token, jose.load_keyset(pub), now=NOW + 10)
    assert es.is_entity_configuration(claims) is True
    assert claims["metadata"]["openid_relying_party"]["client_name"] == "My RP"


def test_federation_metadata_is_included_when_given():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    claims = ec.build_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        authority_hints=["https://ta.example"],
        rp_metadata={"client_name": "My RP"},
        federation_metadata={"organization_name": "Example Org"},
        now=NOW,
    )
    assert claims["metadata"]["federation_entity"]["organization_name"] == "Example Org"
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_entity_configuration.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/federation/entity_configuration.py`:

```python
"""Build and sign the relying party's own Entity Configuration.

Served at ``/.well-known/openid-federation`` (Section 9). It is a self-issued
entity statement whose ``metadata.openid_relying_party`` describes this RP,
whose ``jwks`` are the RP's public federation keys, and whose
``authority_hints`` point at the immediate superior(s) that will issue
subordinate statements about this RP.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from joserfc.jwk import Key

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import jose


def build_rp_entity_configuration(
    *,
    entity_id: str,
    fed_jwks_public: dict[str, object],
    authority_hints: Sequence[str],
    rp_metadata: dict[str, object],
    federation_metadata: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> dict[str, object]:
    """Build the claims of this RP's self-issued Entity Configuration."""
    metadata: dict[str, object] = {"openid_relying_party": rp_metadata}
    if federation_metadata is not None:
        metadata["federation_entity"] = federation_metadata
    return es.build_entity_configuration(
        entity_id=entity_id,
        jwks=fed_jwks_public,
        authority_hints=authority_hints,
        metadata=metadata,
        lifetime=lifetime,
        now=now,
    )


def sign_rp_entity_configuration(
    *,
    entity_id: str,
    fed_jwks_public: dict[str, object],
    fed_signing_key: Key,
    authority_hints: Sequence[str],
    rp_metadata: dict[str, object],
    federation_metadata: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> str:
    """Build and sign this RP's Entity Configuration; returns the compact JWS."""
    claims = build_rp_entity_configuration(
        entity_id=entity_id,
        fed_jwks_public=fed_jwks_public,
        authority_hints=authority_hints,
        rp_metadata=rp_metadata,
        federation_metadata=federation_metadata,
        lifetime=lifetime,
        now=now,
    )
    return jose.sign_entity_statement(claims, fed_signing_key)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_entity_configuration.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/federation/entity_configuration.py tests/federation/test_entity_configuration.py
git commit -m "feat(federation): eigene RP Entity Configuration bauen + signieren"
```

---

## Task 4: Async-Fetch-Schicht + In-Memory-Testföderation

**Files:**
- Create: `src/fastapi_auth/openid/federation/fetch.py`
- Create: `tests/federation/conftest.py` (In-Memory-Testföderation — von späteren Tasks wiederverwendet)
- Test: `tests/federation/test_fetch.py`

**Interfaces:**
- Consumes: `errors.*` (Task 1).
- Produces (aus `federation.fetch`):
  - `ENTITY_STATEMENT_CONTENT_TYPE = "application/entity-statement+jwt"`
  - `well_known_url(entity_id: str) -> str` — `entity_id.rstrip("/") + "/.well-known/openid-federation"`.
  - `async fetch_entity_configuration(client: httpx.AsyncClient, entity_id: str) -> str`
  - `async fetch_subordinate_statement(client: httpx.AsyncClient, fetch_endpoint: str, subject: str) -> str`
- Produces (aus `tests/federation/conftest.py`, für Tasks 5–8):
  - `Entity` (Testhelfer: `entity_id`, `key`, `authority_hints`, `metadata`) mit `.public_jwks()` und `.entity_configuration(now)`.
  - `Federation` mit `add_entity(...)`, `subordinate(issuer_id, subject_id, *, metadata_policy=None, metadata=None, now)`, `mount(router)` (respx-Routen für alle well-known + fetch-Endpoints).
  - pytest-Fixture `federation` und `mock_router` (respx).

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_fetch.py`:

```python
"""Tests for the async federation fetch layer."""

import httpx
import pytest
import respx

from fastapi_auth.openid.federation import fetch
from fastapi_auth.openid.federation.errors import FetchError


def test_well_known_url_strips_trailing_slash_and_suffixes_path():
    assert (
        fetch.well_known_url("https://op.example")
        == "https://op.example/.well-known/openid-federation"
    )
    assert (
        fetch.well_known_url("https://op.example/")
        == "https://op.example/.well-known/openid-federation"
    )
    # Path components are preserved as a suffix (spec Section 9).
    assert (
        fetch.well_known_url("https://host.example/tenant/a")
        == "https://host.example/tenant/a/.well-known/openid-federation"
    )


@pytest.mark.asyncio
async def test_fetch_entity_configuration_returns_body():
    url = fetch.well_known_url("https://op.example")
    with respx.mock:
        respx.get(url).respond(
            200, text="signed.jwt.here", headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )
        async with httpx.AsyncClient() as client:
            body = await fetch.fetch_entity_configuration(client, "https://op.example")
    assert body == "signed.jwt.here"


@pytest.mark.asyncio
async def test_fetch_subordinate_statement_passes_sub_param():
    with respx.mock:
        route = respx.get("https://ta.example/fetch").respond(
            200, text="sub.stmt.jwt", headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )
        async with httpx.AsyncClient() as client:
            body = await fetch.fetch_subordinate_statement(
                client, "https://ta.example/fetch", "https://op.example"
            )
    assert body == "sub.stmt.jwt"
    assert route.calls.last.request.url.params["sub"] == "https://op.example"


@pytest.mark.asyncio
async def test_fetch_raises_on_http_error():
    url = fetch.well_known_url("https://missing.example")
    with respx.mock:
        respx.get(url).respond(404)
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError):
                await fetch.fetch_entity_configuration(client, "https://missing.example")


@pytest.mark.asyncio
async def test_fetch_raises_on_wrong_content_type():
    url = fetch.well_known_url("https://op.example")
    with respx.mock:
        respx.get(url).respond(200, text="<html>", headers={"content-type": "text/html"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError, match="content-type"):
                await fetch.fetch_entity_configuration(client, "https://op.example")
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_fetch.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.openid.federation.fetch`).

- [ ] **Step 3: `fetch.py` implementieren**

`src/fastapi_auth/openid/federation/fetch.py`:

```python
"""Async HTTP fetch layer for federation endpoints.

Retrieves Entity Configurations from ``/.well-known/openid-federation``
(Section 9) and Subordinate Statements from a superior's federation fetch
endpoint with a single ``sub`` query parameter (Section 8.1). Both responses
carry ``application/entity-statement+jwt``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import httpx

from fastapi_auth.openid.federation.errors import FetchError

ENTITY_STATEMENT_CONTENT_TYPE = "application/entity-statement+jwt"
_WELL_KNOWN_SUFFIX = "/.well-known/openid-federation"


def well_known_url(entity_id: str) -> str:
    """Build the entity configuration URL by suffix-concatenation (Section 9)."""
    return entity_id.rstrip("/") + _WELL_KNOWN_SUFFIX


def _check_content_type(response: httpx.Response) -> None:
    content_type = response.headers.get("content-type", "")
    if not content_type.startswith(ENTITY_STATEMENT_CONTENT_TYPE):
        raise FetchError(
            f"unexpected content-type {content_type!r} "
            f"(want {ENTITY_STATEMENT_CONTENT_TYPE!r}) from {response.request.url}"
        )


async def fetch_entity_configuration(client: httpx.AsyncClient, entity_id: str) -> str:
    """GET the self-issued Entity Configuration for ``entity_id``."""
    url = well_known_url(entity_id)
    try:
        response = await client.get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(f"failed to fetch entity configuration from {url}: {exc}") from exc
    _check_content_type(response)
    return response.text


async def fetch_subordinate_statement(
    client: httpx.AsyncClient,
    fetch_endpoint: str,
    subject: str,
) -> str:
    """GET a Subordinate Statement about ``subject`` from a fetch endpoint."""
    try:
        response = await client.get(fetch_endpoint, params={"sub": subject})
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(
            f"failed to fetch subordinate statement for {subject} from {fetch_endpoint}: {exc}"
        ) from exc
    _check_content_type(response)
    return response.text
```

- [ ] **Step 4: In-Memory-Testföderation als `conftest.py` schreiben**

`tests/federation/conftest.py`:

```python
"""In-memory OpenID Federation for tests: keys, statements and respx routes.

Builds a small federation (trust anchor -> intermediate -> leaf) whose entity
configurations and subordinate statements are signed with per-entity test keys,
and mocks the ``.well-known`` and federation fetch endpoints via respx so the
async fetch layer and trust-chain logic can run end-to-end without a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import pytest
import respx
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import fetch, jose

NOW = 1_700_000_000


@dataclass
class Entity:
    """A federation participant with its own signing key."""

    entity_id: str
    key: RSAKey
    authority_hints: list[str] = field(default_factory=list)
    metadata: dict[str, object] | None = None
    fetch_endpoint: str | None = None

    def public_jwks(self) -> dict[str, object]:
        return jose.public_jwks(KeySet([self.key]))

    def entity_configuration(self, *, now: int = NOW) -> str:
        metadata = dict(self.metadata or {})
        if self.fetch_endpoint is not None:
            fed = dict(metadata.get("federation_entity", {}))
            fed["federation_fetch_endpoint"] = self.fetch_endpoint
            metadata["federation_entity"] = fed
        claims = es.build_entity_configuration(
            entity_id=self.entity_id,
            jwks=self.public_jwks(),
            authority_hints=self.authority_hints or None,
            metadata=metadata or None,
            now=now,
        )
        return jose.sign_entity_statement(claims, self.key)


@dataclass
class Federation:
    """A registry of entities plus subordinate-statement minting + routing."""

    entities: dict[str, Entity] = field(default_factory=dict)
    now: int = NOW

    def add_entity(
        self,
        entity_id: str,
        *,
        kid: str | None = None,
        authority_hints: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        fetch_endpoint: str | None = None,
    ) -> Entity:
        key = RSAKey.generate_key(key_size=2048, parameters={"kid": kid or entity_id}, private=True)
        entity = Entity(
            entity_id=entity_id,
            key=key,
            authority_hints=authority_hints or [],
            metadata=metadata,
            fetch_endpoint=fetch_endpoint,
        )
        self.entities[entity_id] = entity
        return entity

    def subordinate(
        self,
        issuer_id: str,
        subject_id: str,
        *,
        metadata_policy: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
        now: int | None = None,
    ) -> str:
        """Mint a subordinate statement (issuer about subject; subject's jwks)."""
        issuer = self.entities[issuer_id]
        subject = self.entities[subject_id]
        claims = es.build_subordinate_statement(
            issuer=issuer_id,
            subject=subject_id,
            jwks=subject.public_jwks(),
            metadata_policy=metadata_policy,
            metadata=metadata,
            now=self.now if now is None else now,
        )
        return jose.sign_entity_statement(claims, issuer.key)

    def trust_anchor_keys(self, entity_id: str) -> dict[str, object]:
        return self.entities[entity_id].public_jwks()

    def mount(self, router: respx.Router) -> None:
        """Register respx routes for all well-known endpoints (fetch: see below)."""
        for entity in self.entities.values():
            router.get(fetch.well_known_url(entity.entity_id)).respond(
                200,
                text=entity.entity_configuration(now=self.now),
                headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE},
            )

    def mount_fetch(self, router: respx.Router, superior_id: str) -> None:
        """Register the fetch endpoint of ``superior_id`` to mint on demand."""
        superior = self.entities[superior_id]
        assert superior.fetch_endpoint is not None

        def _handler(request: httpx.Request) -> httpx.Response:
            sub = request.url.params["sub"]
            return httpx.Response(
                200,
                text=self.subordinate(superior_id, sub, now=self.now),
                headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE},
            )

        router.get(superior.fetch_endpoint).mock(side_effect=_handler)


@pytest.fixture
def federation() -> Federation:
    """A fresh, empty in-memory federation."""
    return Federation()


@pytest.fixture
def mock_router() -> respx.Router:
    """A respx router usable as a context manager in async tests."""
    return respx.mock(assert_all_called=False)
```

- [ ] **Step 5: Test grün laufen lassen (Fetch)**

Run: `uv run pytest tests/federation/test_fetch.py -v`
Expected: alle passed. (conftest wird von pytest automatisch geladen; ein Importfehler dort bricht diese Tests, daher hier mit-verifizieren.)

- [ ] **Step 6: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/federation/fetch.py tests/federation/conftest.py tests/federation/test_fetch.py
git commit -m "feat(federation): async Fetch-Schicht + In-Memory-Testfoederation (respx)"
```

---

## Task 5: Trust-Chain-Auflösung

**Files:**
- Create: `src/fastapi_auth/openid/federation/trust_chain.py`
- Test: `tests/federation/test_trust_chain_resolve.py`

**Interfaces:**
- Consumes: `fetch.*` (Task 4), `jose.peek_claims` (Task 1), `errors.*`.
- Produces:
  - `async resolve_trust_chain(client, leaf_entity_id, trust_anchor_ids, *, max_depth=10) -> list[str]`
  - Rückgabe: Leaf-first-Liste `[leaf_EC, sub_stmt_about_leaf, …, sub_stmt_issued_by_TA]` signierter JWS-Strings. Auflösung folgt `authority_hints`; für jeden Superior wird dessen EC geladen (für Fetch-Endpoint), dann das Subordinate Statement über die untere Entity vom Fetch-Endpoint geholt. Zweige, die nicht an einem `trust_anchor_ids`-Anchor enden, werden verworfen; Loop-Schutz über `visited`. Kein `authority_hints`-Zweig erfolgreich ⇒ `TrustChainError`.
  - **Nur Auflösung, keine Signaturprüfung** (die macht Task 6). `peek_claims` wird ausschließlich zur Navigation genutzt.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_trust_chain_resolve.py`:

```python
"""Tests for trust chain resolution (navigation only, no signature checks)."""

import httpx
import pytest

from fastapi_auth.openid.federation import jose, trust_chain
from fastapi_auth.openid.federation.errors import TrustChainError


def _build_three_level(federation):
    """TA -> intermediate -> leaf, with fetch endpoints on TA and intermediate."""
    federation.add_entity(
        "https://ta.example",
        fetch_endpoint="https://ta.example/fetch",
        metadata={"federation_entity": {"organization_name": "TA"}},
    )
    federation.add_entity(
        "https://im.example",
        authority_hints=["https://ta.example"],
        fetch_endpoint="https://im.example/fetch",
    )
    federation.add_entity(
        "https://leaf.example",
        authority_hints=["https://im.example"],
        metadata={"openid_provider": {"issuer": "https://leaf.example"}},
    )


@pytest.mark.asyncio
async def test_resolves_leaf_first_chain_to_anchor(federation, mock_router):
    _build_three_level(federation)
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")
    federation.mount_fetch(mock_router, "https://im.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            chain = await trust_chain.resolve_trust_chain(
                client, "https://leaf.example", ["https://ta.example"]
            )

    claims = [jose.peek_claims(t) for t in chain]
    assert claims[0]["iss"] == claims[0]["sub"] == "https://leaf.example"  # leaf EC
    assert claims[1]["iss"] == "https://im.example"  # subordinate about leaf
    assert claims[1]["sub"] == "https://leaf.example"
    assert claims[2]["iss"] == "https://ta.example"  # subordinate about intermediate
    assert claims[2]["sub"] == "https://im.example"
    assert len(chain) == 3


@pytest.mark.asyncio
async def test_resolves_direct_leaf_under_anchor(federation, mock_router):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
    federation.add_entity("https://leaf.example", authority_hints=["https://ta.example"])
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            chain = await trust_chain.resolve_trust_chain(
                client, "https://leaf.example", ["https://ta.example"]
            )
    assert len(chain) == 2
    assert jose.peek_claims(chain[1])["iss"] == "https://ta.example"


@pytest.mark.asyncio
async def test_raises_when_no_branch_reaches_configured_anchor(federation, mock_router):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
    federation.add_entity("https://leaf.example", authority_hints=["https://ta.example"])
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            with pytest.raises(TrustChainError):
                # A different anchor is configured -> chain must not be trusted.
                await trust_chain.resolve_trust_chain(
                    client, "https://leaf.example", ["https://other-ta.example"]
                )
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_trust_chain_resolve.py -v`
Expected: FAIL (`ModuleNotFoundError` / kein `resolve_trust_chain`).

- [ ] **Step 3: Auflösung implementieren**

`src/fastapi_auth/openid/federation/trust_chain.py` (nur der Auflösungs-Teil; Task 6 ergänzt Validierung, Task 8 Orchestrierung — Datei jetzt anlegen):

```python
"""Resolve and validate OpenID Federation trust chains (Sections 4, 10).

Resolution walks ``authority_hints`` from the leaf upward, fetching each
superior's Entity Configuration (to locate its federation fetch endpoint) and
then the Subordinate Statement about the entity below it, until it reaches a
*configured* Trust Anchor. Resolution uses unverified ``peek_claims`` purely to
navigate; every statement is cryptographically verified later, in
``validate_trust_chain`` (Task 6).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from fastapi_auth.openid.federation import fetch, jose
from fastapi_auth.openid.federation.errors import FetchError, TrustChainError


async def _walk(
    client: httpx.AsyncClient,
    subject_id: str,
    subject_claims: dict[str, object],
    trust_anchor_ids: frozenset[str],
    visited: frozenset[str],
    depth: int,
) -> list[str] | None:
    """Return subordinate statements from ``subject`` up to a configured anchor."""
    hints = subject_claims.get("authority_hints", [])
    if not isinstance(hints, list):
        return None
    for superior_id in hints:
        if not isinstance(superior_id, str) or superior_id in visited:
            continue
        try:
            superior_ec = await fetch.fetch_entity_configuration(client, superior_id)
        except FetchError:
            continue
        superior_claims = jose.peek_claims(superior_ec)
        endpoint = _fetch_endpoint(superior_claims)
        if endpoint is None:
            continue
        try:
            subordinate = await fetch.fetch_subordinate_statement(client, endpoint, subject_id)
        except FetchError:
            continue
        if superior_id in trust_anchor_ids:
            return [subordinate]
        if depth <= 1:
            continue
        rest = await _walk(
            client,
            superior_id,
            superior_claims,
            trust_anchor_ids,
            visited | {superior_id},
            depth - 1,
        )
        if rest is not None:
            return [subordinate, *rest]
    return None


def _fetch_endpoint(claims: dict[str, object]) -> str | None:
    metadata = claims.get("metadata")
    if not isinstance(metadata, dict):
        return None
    federation_entity = metadata.get("federation_entity")
    if not isinstance(federation_entity, dict):
        return None
    endpoint = federation_entity.get("federation_fetch_endpoint")
    return endpoint if isinstance(endpoint, str) else None


async def resolve_trust_chain(
    client: httpx.AsyncClient,
    leaf_entity_id: str,
    trust_anchor_ids: Sequence[str],
    *,
    max_depth: int = 10,
) -> list[str]:
    """Resolve a leaf-first trust chain terminating at a configured anchor."""
    anchors = frozenset(trust_anchor_ids)
    leaf_ec = await fetch.fetch_entity_configuration(client, leaf_entity_id)
    leaf_claims = jose.peek_claims(leaf_ec)
    tail = await _walk(
        client,
        leaf_entity_id,
        leaf_claims,
        anchors,
        frozenset({leaf_entity_id}),
        max_depth,
    )
    if tail is None:
        raise TrustChainError(
            f"no trust chain from {leaf_entity_id} to a configured trust anchor {sorted(anchors)}"
        )
    return [leaf_ec, *tail]
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_trust_chain_resolve.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/federation/trust_chain.py tests/federation/test_trust_chain_resolve.py
git commit -m "feat(federation): Trust-Chain-Aufloesung (authority_hints -> Trust Anchor)"
```

---

## Task 6: Trust-Chain-Validierung (adversarial)

**Files:**
- Modify: `src/fastapi_auth/openid/federation/trust_chain.py` (Validierung ergänzen)
- Test: `tests/federation/test_trust_chain_validate.py`

**Interfaces:**
- Consumes: `entity_statement.verify_statement`/`check_structure`/`check_time`, `jose.*`, `errors.*`.
- Produces:
  - `@dataclass(frozen=True) ValidatedChain`: `statements: tuple[dict, ...]` (verifizierte Claims, Leaf-first), `leaf: dict`, `trust_anchor_id: str`, `exp: int` (min über Kette), `subordinate_statements: tuple[dict, ...]` (alle außer Leaf-EC).
  - `validate_trust_chain(chain: Sequence[str], trust_anchors: Mapping[str, dict], *, algorithms=DEFAULT_SIGNING_ALGORITHMS, leeway=0, now=None) -> ValidatedChain`
  - Regeln exakt: `chain[0]` self-signed (`iss==sub`, verifiziert mit `chain[0].jwks`); für `j=0..n-2` `chain[j]` verifiziert mit `chain[j+1].jwks` **und** `chain[j].iss == chain[j+1].sub`; `chain[n-1].iss` MUSS in `trust_anchors` sein und wird mit den **konfigurierten** TA-Keys verifiziert; alle Statements Struktur+Zeit ok; `exp = min(exp)`.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_trust_chain_validate.py`:

```python
"""Adversarial tests for trust chain validation."""

import pytest

from fastapi_auth.openid.federation import jose, trust_chain
from fastapi_auth.openid.federation.errors import SignatureError, TrustChainError

NOW = 1_700_000_000


def _three_level(federation):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
    federation.add_entity(
        "https://im.example", authority_hints=["https://ta.example"], fetch_endpoint="https://im.example/fetch"
    )
    federation.add_entity(
        "https://leaf.example",
        authority_hints=["https://im.example"],
        metadata={"openid_provider": {"issuer": "https://leaf.example"}},
    )


def _valid_chain(federation) -> list[str]:
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    sub_about_leaf = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    return [leaf_ec, sub_about_leaf, sub_about_im]


def test_valid_chain_passes(federation):
    _three_level(federation)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    result = trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)
    assert result.trust_anchor_id == "https://ta.example"
    assert result.leaf["sub"] == "https://leaf.example"
    assert result.exp == min(s["exp"] for s in result.statements)


def test_rejects_chain_not_ending_at_configured_anchor(federation):
    _three_level(federation)
    anchors = {"https://other.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="configured trust anchor"):
        trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)


def test_rejects_forged_subordinate_signature(federation):
    from fastapi_auth.openid.federation import entity_statement as es

    _three_level(federation)
    federation.add_entity("https://attacker.example")
    leaf = federation.entities["https://leaf.example"]
    attacker = federation.entities["https://attacker.example"]
    # Keep the linkage valid (iss=im, sub=leaf, jwks=leaf keys) so we reach the
    # signature check, but sign with the ATTACKER's key instead of the intermediate's.
    claims = es.build_subordinate_statement(
        issuer="https://im.example",
        subject="https://leaf.example",
        jwks=leaf.public_jwks(),
        now=NOW,
    )
    forged = jose.sign_entity_statement(claims, attacker.key)
    leaf_ec = leaf.entity_configuration(now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    chain = [leaf_ec, forged, sub_about_im]
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    # forged is verified against chain[2].jwks (the intermediate's keys) -> no matching kid.
    with pytest.raises(SignatureError):
        trust_chain.validate_trust_chain(chain, anchors, now=NOW + 10)


def test_rejects_tampered_ta_key(federation):
    _three_level(federation)
    federation.add_entity("https://impostor.example")
    # Configure the correct anchor id but with the WRONG public keys.
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://impostor.example")}
    with pytest.raises(SignatureError):
        trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)


def test_rejects_broken_issuer_subject_linkage(federation):
    _three_level(federation)
    federation.add_entity("https://rogue.example", fetch_endpoint="https://rogue.example/fetch")
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    # subordinate about a DIFFERENT subject than the leaf -> linkage break at chain[0].iss vs chain[1].sub
    sub_about_rogue = federation.subordinate("https://im.example", "https://rogue.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="linkage"):
        trust_chain.validate_trust_chain([leaf_ec, sub_about_rogue, sub_about_im], anchors, now=NOW + 10)


def test_rejects_expired_statement(federation):
    _three_level(federation)
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    sub_about_leaf = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="expired"):
        # Far in the future -> every statement's exp is in the past.
        trust_chain.validate_trust_chain([leaf_ec, sub_about_leaf, sub_about_im], anchors, now=NOW + 100_000)


def test_rejects_leaf_that_is_not_self_issued(federation):
    _three_level(federation)
    # Use a subordinate statement (iss != sub) in the leaf slot.
    not_self = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="self-issued"):
        trust_chain.validate_trust_chain([not_self, sub_about_im], anchors, now=NOW + 10)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_trust_chain_validate.py -v`
Expected: FAIL (kein `validate_trust_chain`/`ValidatedChain`).

- [ ] **Step 3: Validierung ergänzen**

In `src/fastapi_auth/openid/federation/trust_chain.py` oben die Imports ergänzen und die Validierung anhängen:

```python
# --- add to the existing imports at the top of trust_chain.py ---
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation.errors import TrustChainError  # already imported; keep single import
```

Hinweis für die Umsetzung: konsolidiere die Imports (kein doppelter `Sequence`/`TrustChainError`-Import); füge `Mapping`, `dataclass`, `es` hinzu. Dann am Dateiende anhängen:

```python
@dataclass(frozen=True)
class ValidatedChain:
    """A cryptographically validated trust chain (leaf-first)."""

    statements: tuple[dict[str, object], ...]
    trust_anchor_id: str
    exp: int

    @property
    def leaf(self) -> dict[str, object]:
        return self.statements[0]

    @property
    def subordinate_statements(self) -> tuple[dict[str, object], ...]:
        return self.statements[1:]


def _keyset_from_statement(claims: dict[str, object]):
    jwks = claims.get("jwks")
    if not isinstance(jwks, dict):
        raise TrustChainError("entity statement has no usable jwks")
    return jose.load_keyset(jwks)


def validate_trust_chain(
    chain: Sequence[str],
    trust_anchors: Mapping[str, dict[str, object]],
    *,
    algorithms: Sequence[str] = jose.DEFAULT_SIGNING_ALGORITHMS,
    leeway: int = 0,
    now: int | None = None,
) -> ValidatedChain:
    """Validate every signature, linkage, freshness and the anchor (Section 10.2)."""
    if not chain:
        raise TrustChainError("empty trust chain")

    peeked = [jose.peek_claims(token) for token in chain]
    for claims in peeked:
        es.check_structure(claims)
        es.check_time(claims, leeway=leeway, now=now)

    # Leaf must be self-issued.
    if peeked[0].get("iss") != peeked[0].get("sub"):
        raise TrustChainError("leaf entity configuration is not self-issued")

    # Issuer/subject linkage: chain[j].iss == chain[j+1].sub.
    for j in range(len(chain) - 1):
        if peeked[j].get("iss") != peeked[j + 1].get("sub"):
            raise TrustChainError(
                f"broken issuer/subject linkage at position {j}: "
                f"{peeked[j].get('iss')!r} != {peeked[j + 1].get('sub')!r}"
            )

    # Signatures for j = 0..n-2: chain[j] verified with the key set from chain[j+1].jwks.
    verified: list[dict[str, object]] = []
    for j in range(len(chain) - 1):
        keyset = _keyset_from_statement(peeked[j + 1])
        verified.append(
            es.verify_statement(chain[j], keyset, algorithms=algorithms, leeway=leeway, now=now)
        )

    # Top statement (issued by the Trust Anchor) verified with configured anchor keys.
    top_claims = peeked[-1]
    anchor_id = top_claims.get("iss")
    if not isinstance(anchor_id, str) or anchor_id not in trust_anchors:
        raise TrustChainError(
            f"trust chain does not terminate at a configured trust anchor "
            f"(top issuer: {anchor_id!r})"
        )
    anchor_keyset = jose.load_keyset(trust_anchors[anchor_id])
    verified.append(
        es.verify_statement(chain[-1], anchor_keyset, algorithms=algorithms, leeway=leeway, now=now)
    )

    chain_exp = min(int(claims["exp"]) for claims in verified)
    return ValidatedChain(
        statements=tuple(verified),
        trust_anchor_id=anchor_id,
        exp=chain_exp,
    )
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_trust_chain_validate.py -v`
Expected: alle passed. (Falls `test_rejects_forged_subordinate_signature` nicht wirft: prüfe, dass die Signatur von `chain[j]` wirklich gegen `chain[j+1].jwks` läuft — der forged-Fall hat `iss` = im, aber die Signatur stammt vom Attacker-Key, der nicht in `sub_about_im.jwks` (= im-Keys) liegt.)

- [ ] **Step 5: Lint + Teil-Suite**

Run: `uv run pytest tests/federation -q && make lint`
Expected: grün; exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/federation/trust_chain.py tests/federation/test_trust_chain_validate.py
git commit -m "feat(federation): Trust-Chain-Validierung (Signaturkette, Anchor, Zeit)"
```

---

## Task 7: Metadata Policy — Merge + Apply

**Files:**
- Create: `src/fastapi_auth/openid/federation/metadata_policy.py`
- Test: `tests/federation/test_metadata_policy.py`

**Interfaces:**
- Consumes: `errors.MetadataPolicyError`.
- Produces:
  - `KNOWN_OPERATORS: frozenset[str]` = `{value, add, default, one_of, subset_of, superset_of, essential}`.
  - `APPLICATION_ORDER: tuple[str, ...]` = `("value", "add", "default", "one_of", "subset_of", "superset_of", "essential")`.
  - `merge_policies(policies: Sequence[dict], *, critical_operators: Sequence[str] = ()) -> dict` — kombiniert Policies **in gegebener Reihenfolge (TA→Leaf)** auf drei Ebenen (entity_type → parameter → operator). Konflikte ⇒ `MetadataPolicyError`. Unbekannter Operator, der in `critical_operators` steht ⇒ `MetadataPolicyError`; unbekannter, nicht-kritischer Operator ⇒ ignoriert.
  - `apply_policy(metadata: dict, policy: dict) -> dict` — wendet die Parameter-Policies eines Entity-Types in fester Operator-Reihenfolge auf ein Metadata-Dict an. Verletzung (`essential` fehlt, `one_of`/`superset_of` nicht erfüllt, resultierender `null`) ⇒ `MetadataPolicyError`.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_metadata_policy.py`:

```python
"""Tests for metadata policy merge and application (Section 6.1)."""

import pytest

from fastapi_auth.openid.federation import metadata_policy as mp
from fastapi_auth.openid.federation.errors import MetadataPolicyError


# --- apply_policy ---

def test_apply_value_overrides():
    out = mp.apply_policy({"a": "x"}, {"a": {"value": "forced"}})
    assert out["a"] == "forced"


def test_apply_value_null_removes_parameter():
    out = mp.apply_policy({"a": "x"}, {"a": {"value": None}})
    assert "a" not in out


def test_apply_default_only_when_missing():
    assert mp.apply_policy({}, {"a": {"default": "d"}})["a"] == "d"
    assert mp.apply_policy({"a": "kept"}, {"a": {"default": "d"}})["a"] == "kept"


def test_apply_add_unions_lists():
    out = mp.apply_policy({"a": ["x"]}, {"a": {"add": ["y", "x"]}})
    assert sorted(out["a"]) == ["x", "y"]


def test_apply_subset_of_intersects():
    out = mp.apply_policy({"a": ["x", "y", "z"]}, {"a": {"subset_of": ["x", "z"]}})
    assert sorted(out["a"]) == ["x", "z"]


def test_apply_one_of_ok_and_violation():
    assert mp.apply_policy({"a": "x"}, {"a": {"one_of": ["x", "y"]}})["a"] == "x"
    with pytest.raises(MetadataPolicyError, match="one_of"):
        mp.apply_policy({"a": "z"}, {"a": {"one_of": ["x", "y"]}})


def test_apply_superset_of_requires_all():
    assert mp.apply_policy({"a": ["x", "y", "z"]}, {"a": {"superset_of": ["x", "y"]}})["a"]
    with pytest.raises(MetadataPolicyError, match="superset_of"):
        mp.apply_policy({"a": ["x"]}, {"a": {"superset_of": ["x", "y"]}})


def test_apply_essential_missing_raises():
    with pytest.raises(MetadataPolicyError, match="essential"):
        mp.apply_policy({}, {"a": {"essential": True}})


def test_apply_essential_false_missing_is_ok():
    out = mp.apply_policy({}, {"a": {"essential": False}})
    assert "a" not in out


def test_apply_operator_order_value_then_subset():
    # value sets ["x","y"], subset_of keeps ["x"] -> final ["x"]
    out = mp.apply_policy({"a": ["z"]}, {"a": {"value": ["x", "y"], "subset_of": ["x"]}})
    assert out["a"] == ["x"]


# --- merge_policies (TA -> leaf order) ---

def test_merge_value_equal_ok_conflict_raises():
    merged = mp.merge_policies(
        [{"op": {"p": {"value": "v"}}}, {"op": {"p": {"value": "v"}}}]
    )
    assert merged["op"]["p"]["value"] == "v"
    with pytest.raises(MetadataPolicyError, match="value"):
        mp.merge_policies([{"op": {"p": {"value": "a"}}}, {"op": {"p": {"value": "b"}}}])


def test_merge_add_unions():
    merged = mp.merge_policies(
        [{"op": {"p": {"add": ["x"]}}}, {"op": {"p": {"add": ["y"]}}}]
    )
    assert sorted(merged["op"]["p"]["add"]) == ["x", "y"]


def test_merge_one_of_intersects_empty_raises():
    merged = mp.merge_policies(
        [{"op": {"p": {"one_of": ["x", "y"]}}}, {"op": {"p": {"one_of": ["y", "z"]}}}]
    )
    assert merged["op"]["p"]["one_of"] == ["y"]
    with pytest.raises(MetadataPolicyError, match="one_of"):
        mp.merge_policies(
            [{"op": {"p": {"one_of": ["x"]}}}, {"op": {"p": {"one_of": ["z"]}}}]
        )


def test_merge_subset_of_intersects():
    merged = mp.merge_policies(
        [{"op": {"p": {"subset_of": ["a", "b", "c"]}}}, {"op": {"p": {"subset_of": ["b", "c", "d"]}}}]
    )
    assert sorted(merged["op"]["p"]["subset_of"]) == ["b", "c"]


def test_merge_new_entity_types_and_parameters_pass_through():
    merged = mp.merge_policies(
        [{"op": {"p": {"value": "v"}}}, {"op2": {"q": {"default": "d"}}}]
    )
    assert merged["op"]["p"]["value"] == "v"
    assert merged["op2"]["q"]["default"] == "d"


def test_merge_unknown_critical_operator_raises():
    with pytest.raises(MetadataPolicyError, match="critical"):
        mp.merge_policies([{"op": {"p": {"weird_op": 1}}}], critical_operators=["weird_op"])


def test_merge_unknown_non_critical_operator_is_ignored():
    merged = mp.merge_policies([{"op": {"p": {"weird_op": 1, "value": "v"}}}])
    assert merged["op"]["p"]["value"] == "v"
    assert "weird_op" not in merged["op"]["p"]
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_metadata_policy.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implementieren**

`src/fastapi_auth/openid/federation/metadata_policy.py`:

```python
"""Merge and apply OpenID Federation metadata policies (Section 6.1).

A metadata policy is a three-level mapping ``entity_type -> parameter ->
operator -> value``. Policies from the trust chain are merged top-down
(Trust Anchor first, leaf's immediate superior last); the merged policy is then
applied to the leaf's metadata for one entity type. Operators are applied in the
fixed order ``value, add, default, one_of, subset_of, superset_of, essential``.

Once a policy has constrained a parameter, a more subordinate policy may only
constrain it further, never relax it — conflicting merges make the whole trust
chain invalid (Section 6.1.1).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.openid.federation.errors import MetadataPolicyError

KNOWN_OPERATORS: frozenset[str] = frozenset(
    {"value", "add", "default", "one_of", "subset_of", "superset_of", "essential"}
)
APPLICATION_ORDER: tuple[str, ...] = (
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
)

_MISSING = object()


def _as_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else [value]


def _union(left: object, right: object) -> list[object]:
    result = list(_as_list(left))
    for item in _as_list(right):
        if item not in result:
            result.append(item)
    return result


def _intersect(left: object, right: object) -> list[object]:
    right_list = _as_list(right)
    return [item for item in _as_list(left) if item in right_list]


# --- merge -------------------------------------------------------------------

def _merge_operator(operator: str, current: object, incoming: object) -> object:
    if operator in {"value", "default"}:
        if current != incoming:
            raise MetadataPolicyError(
                f"conflicting {operator!r} on merge: {current!r} != {incoming!r}"
            )
        return current
    if operator in {"add", "superset_of"}:
        return _union(current, incoming)
    if operator == "one_of":
        merged = _intersect(current, incoming)
        if not merged:
            raise MetadataPolicyError("merging one_of produced an empty set")
        return merged
    if operator == "subset_of":
        return _intersect(current, incoming)
    if operator == "essential":
        return bool(current) or bool(incoming)
    raise MetadataPolicyError(f"cannot merge unknown operator {operator!r}")


def _merge_parameter(
    current: dict[str, object],
    incoming: dict[str, object],
    critical: frozenset[str],
) -> dict[str, object]:
    merged = dict(current)
    for operator, value in incoming.items():
        if operator not in KNOWN_OPERATORS:
            if operator in critical:
                raise MetadataPolicyError(f"unknown critical policy operator {operator!r}")
            continue  # unknown, non-critical -> ignore
        if operator in merged:
            merged[operator] = _merge_operator(operator, merged[operator], value)
        else:
            merged[operator] = value
    return merged


def merge_policies(
    policies: Sequence[dict[str, object]],
    *,
    critical_operators: Sequence[str] = (),
) -> dict[str, object]:
    """Merge a chain of metadata policies (ordered Trust Anchor -> leaf)."""
    critical = frozenset(critical_operators)
    merged: dict[str, object] = {}
    for policy in policies:
        for entity_type, params in policy.items():
            if not isinstance(params, dict):
                raise MetadataPolicyError(f"policy for {entity_type!r} is not an object")
            entity_bucket = dict(merged.get(entity_type, {}))
            for parameter, operators in params.items():
                if not isinstance(operators, dict):
                    raise MetadataPolicyError(
                        f"policy for {entity_type}.{parameter} is not an object"
                    )
                entity_bucket[parameter] = _merge_parameter(
                    entity_bucket.get(parameter, {}), operators, critical
                )
            merged[entity_type] = entity_bucket
    return merged


# --- apply -------------------------------------------------------------------

def _apply_operator(operator: str, spec: object, value: object, parameter: str) -> object:
    if operator == "value":
        return _MISSING if spec is None else spec
    if operator == "add":
        base = value if value is not _MISSING else []
        return _union(base, spec)
    if operator == "default":
        return spec if value is _MISSING else value
    if operator == "one_of":
        if value is _MISSING:
            return value
        if value not in _as_list(spec):
            raise MetadataPolicyError(f"{parameter}: value {value!r} not in one_of {spec!r}")
        return value
    if operator == "subset_of":
        if value is _MISSING:
            return value
        return _intersect(value, spec)
    if operator == "superset_of":
        if value is _MISSING:
            return value
        missing = [item for item in _as_list(spec) if item not in _as_list(value)]
        if missing:
            raise MetadataPolicyError(f"{parameter}: value missing superset_of members {missing!r}")
        return value
    if operator == "essential":
        if spec and value is _MISSING:
            raise MetadataPolicyError(f"{parameter}: essential parameter is absent")
        return value
    raise MetadataPolicyError(f"cannot apply unknown operator {operator!r}")


def apply_policy(metadata: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    """Apply one entity type's parameter policies to a metadata dict."""
    result = dict(metadata)
    for parameter, operators in policy.items():
        value: object = result.get(parameter, _MISSING)
        for operator in APPLICATION_ORDER:
            if operator in operators:
                value = _apply_operator(operator, operators[operator], value, parameter)
        if value is _MISSING:
            result.pop(parameter, None)
        elif value is None:
            raise MetadataPolicyError(f"{parameter}: policy produced a null value")
        else:
            result[parameter] = value
    return result
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_metadata_policy.py -v`
Expected: alle passed.

- [ ] **Step 5: Lint**

Run: `make lint`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/fastapi_auth/openid/federation/metadata_policy.py tests/federation/test_metadata_policy.py
git commit -m "feat(federation): Metadata-Policy Merge + Apply (Operator-Semantik)"
```

---

## Task 8: Orchestrierung — `resolve_and_validate` + Resolved Metadata + Cache

**Files:**
- Modify: `src/fastapi_auth/openid/federation/trust_chain.py` (Orchestrierung + resolved metadata + Cache)
- Modify: `src/fastapi_auth/openid/federation/__init__.py` (Public-API-Re-Exports der Federation-Schicht)
- Test: `tests/federation/test_resolve_and_validate.py`

**Interfaces:**
- Consumes: `resolve_trust_chain`, `validate_trust_chain` (Tasks 5–6), `metadata_policy.*` (Task 7).
- Produces:
  - `@dataclass(frozen=True) ResolvedEntity`: `entity_id: str`, `entity_type: str`, `metadata: dict` (validierte, policy-aufgelöste Metadaten), `trust_anchor_id: str`, `exp: int`, `chain: ValidatedChain`.
  - `resolve_metadata(chain: ValidatedChain, *, entity_type: str = "openid_provider") -> dict` — wendet Subordinate-`metadata`-Overrides (Section 6.1.4.2 Schritt 1) an, merged Policies **TA→Leaf**, appliziert auf die Leaf-Metadaten des `entity_type`. Fehlt der Entity-Type ⇒ `TrustChainError`.
  - `async resolve_and_validate(client, entity_id, trust_anchors, *, entity_type="openid_provider", algorithms=DEFAULT_SIGNING_ALGORITHMS, leeway=0, now=None) -> ResolvedEntity` — resolve → validate → resolve_metadata.
  - `TrustChainCache` — einfacher exp-respektierender In-Memory-Cache: `get(entity_id, *, now=None) -> ResolvedEntity | None`, `set(resolved: ResolvedEntity) -> None`. Eintrag gilt bis `min(resolved.exp)`.
- Produces (Re-Exports in `federation/__init__.py`): `resolve_and_validate`, `resolve_trust_chain`, `validate_trust_chain`, `ResolvedEntity`, `ValidatedChain`, `TrustChainCache`, `sign_rp_entity_configuration`, und die Error-Typen.

- [ ] **Step 1: Failing test schreiben**

`tests/federation/test_resolve_and_validate.py`:

```python
"""End-to-end tests: resolve + validate + metadata policy over the in-memory federation."""

import httpx
import pytest

from fastapi_auth.openid.federation import trust_chain
from fastapi_auth.openid.federation.errors import MetadataPolicyError

NOW = 1_700_000_000


def _federation_with_policy(federation):
    federation.add_entity(
        "https://ta.example",
        fetch_endpoint="https://ta.example/fetch",
    )
    federation.add_entity(
        "https://im.example",
        authority_hints=["https://ta.example"],
        fetch_endpoint="https://im.example/fetch",
    )
    federation.add_entity(
        "https://op.example",
        authority_hints=["https://im.example"],
        metadata={
            "openid_provider": {
                "issuer": "https://op.example",
                "token_endpoint": "https://op.example/token",
                "grant_types_supported": ["authorization_code", "implicit"],
            }
        },
    )


@pytest.mark.asyncio
async def test_resolve_and_validate_returns_policy_resolved_metadata(federation, mock_router):
    _federation_with_policy(federation)
    federation.mount(mock_router)

    # TA restricts grant types to authorization_code via a subordinate about the intermediate;
    # mount a custom fetch that carries the policy.
    def ta_fetch(request):
        sub = request.url.params["sub"]
        return httpx.Response(
            200,
            text=federation.subordinate(
                "https://ta.example",
                sub,
                metadata_policy={
                    "openid_provider": {"grant_types_supported": {"subset_of": ["authorization_code"]}}
                },
                now=NOW,
            ),
            headers={"content-type": "application/entity-statement+jwt"},
        )

    mock_router.get("https://ta.example/fetch").mock(side_effect=ta_fetch)
    federation.mount_fetch(mock_router, "https://im.example")

    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with mock_router:
        async with httpx.AsyncClient() as client:
            resolved = await trust_chain.resolve_and_validate(
                client, "https://op.example", anchors, now=NOW + 10
            )

    assert resolved.entity_id == "https://op.example"
    assert resolved.metadata["issuer"] == "https://op.example"
    assert resolved.metadata["token_endpoint"] == "https://op.example/token"
    # policy applied: implicit removed by subset_of
    assert resolved.metadata["grant_types_supported"] == ["authorization_code"]
    assert resolved.trust_anchor_id == "https://ta.example"


@pytest.mark.asyncio
async def test_resolve_and_validate_policy_violation_invalidates(federation, mock_router):
    _federation_with_policy(federation)
    federation.mount(mock_router)

    def ta_fetch(request):
        sub = request.url.params["sub"]
        return httpx.Response(
            200,
            text=federation.subordinate(
                "https://ta.example",
                sub,
                metadata_policy={"openid_provider": {"issuer": {"value": "https://forced.example"}}},
                now=NOW,
            ),
            headers={"content-type": "application/entity-statement+jwt"},
        )

    mock_router.get("https://ta.example/fetch").mock(side_effect=ta_fetch)
    federation.mount_fetch(mock_router, "https://im.example")

    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with mock_router:
        async with httpx.AsyncClient() as client:
            resolved = await trust_chain.resolve_and_validate(
                client, "https://op.example", anchors, now=NOW + 10
            )
    # value operator forces issuer; resolved metadata reflects the policy.
    assert resolved.metadata["issuer"] == "https://forced.example"


def test_cache_respects_expiry(federation):
    _federation_with_policy(federation)
    cache = trust_chain.TrustChainCache()
    chain = trust_chain.ValidatedChain(
        statements=({"sub": "https://op.example", "exp": NOW + 100},),
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
    )
    resolved = trust_chain.ResolvedEntity(
        entity_id="https://op.example",
        entity_type="openid_provider",
        metadata={"issuer": "https://op.example"},
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
        chain=chain,
    )
    cache.set(resolved)
    assert cache.get("https://op.example", now=NOW + 50) is resolved
    assert cache.get("https://op.example", now=NOW + 200) is None  # expired
    assert cache.get("https://unknown.example", now=NOW) is None


def test_resolve_metadata_missing_entity_type_raises(federation):
    from fastapi_auth.openid.federation.errors import TrustChainError

    _federation_with_policy(federation)
    chain = trust_chain.ValidatedChain(
        statements=(
            {"iss": "https://op.example", "sub": "https://op.example", "exp": NOW + 100, "metadata": {}},
            {"iss": "https://ta.example", "sub": "https://op.example", "exp": NOW + 100},
        ),
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
    )
    with pytest.raises(TrustChainError, match="openid_provider"):
        trust_chain.resolve_metadata(chain, entity_type="openid_provider")
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/federation/test_resolve_and_validate.py -v`
Expected: FAIL (kein `resolve_and_validate`/`resolve_metadata`/`ResolvedEntity`/`TrustChainCache`).

- [ ] **Step 3: Orchestrierung ergänzen**

Am Ende von `src/fastapi_auth/openid/federation/trust_chain.py` anhängen (Import von `metadata_policy` oben ergänzen):

```python
# --- add near the top imports of trust_chain.py ---
from fastapi_auth.openid.federation import metadata_policy as mp
```

```python
@dataclass(frozen=True)
class ResolvedEntity:
    """A trusted entity with policy-resolved metadata for one entity type."""

    entity_id: str
    entity_type: str
    metadata: dict[str, object]
    trust_anchor_id: str
    exp: int
    chain: ValidatedChain


def _leaf_metadata(chain: ValidatedChain, entity_type: str) -> dict[str, object]:
    metadata = chain.leaf.get("metadata")
    base: dict[str, object] = {}
    if isinstance(metadata, dict) and isinstance(metadata.get(entity_type), dict):
        base = dict(metadata[entity_type])
    # Section 6.1.4.2 step 1: a subordinate statement's `metadata` overrides the leaf's.
    for statement in chain.subordinate_statements:
        override = statement.get("metadata")
        if isinstance(override, dict) and isinstance(override.get(entity_type), dict):
            base.update(override[entity_type])
    return base


def resolve_metadata(chain: ValidatedChain, *, entity_type: str = "openid_provider") -> dict[str, object]:
    """Apply subordinate metadata overrides + merged policy to the leaf metadata."""
    base = _leaf_metadata(chain, entity_type)
    if not base:
        raise TrustChainError(f"no {entity_type!r} metadata in the trust chain leaf")

    # Collect policies from the chain, ordered Trust Anchor -> leaf (reverse of leaf-first).
    critical: list[str] = []
    policies: list[dict[str, object]] = []
    for statement in reversed(chain.subordinate_statements):
        crit = statement.get("metadata_policy_crit")
        if isinstance(crit, list):
            critical.extend(str(name) for name in crit)
        policy = statement.get("metadata_policy")
        if isinstance(policy, dict):
            policies.append(policy)

    if not policies:
        return base

    merged = mp.merge_policies(policies, critical_operators=critical)
    entity_policy = merged.get(entity_type)
    if not isinstance(entity_policy, dict):
        return base
    return mp.apply_policy(base, entity_policy)


async def resolve_and_validate(
    client: httpx.AsyncClient,
    entity_id: str,
    trust_anchors: Mapping[str, dict[str, object]],
    *,
    entity_type: str = "openid_provider",
    algorithms: Sequence[str] = jose.DEFAULT_SIGNING_ALGORITHMS,
    leeway: int = 0,
    now: int | None = None,
    max_depth: int = 10,
) -> ResolvedEntity:
    """Resolve, validate and policy-resolve an entity's metadata end to end."""
    chain_tokens = await resolve_trust_chain(
        client, entity_id, list(trust_anchors), max_depth=max_depth
    )
    validated = validate_trust_chain(
        chain_tokens, trust_anchors, algorithms=algorithms, leeway=leeway, now=now
    )
    metadata = resolve_metadata(validated, entity_type=entity_type)
    return ResolvedEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        metadata=metadata,
        trust_anchor_id=validated.trust_anchor_id,
        exp=validated.exp,
        chain=validated,
    )


class TrustChainCache:
    """A minimal in-memory cache keyed by entity id, honoring the chain exp."""

    def __init__(self) -> None:
        self._entries: dict[str, ResolvedEntity] = {}

    def get(self, entity_id: str, *, now: int | None = None) -> ResolvedEntity | None:
        moment = jose.now_epoch() if now is None else now
        resolved = self._entries.get(entity_id)
        if resolved is None:
            return None
        if resolved.exp <= moment:
            self._entries.pop(entity_id, None)
            return None
        return resolved

    def set(self, resolved: ResolvedEntity) -> None:
        self._entries[resolved.entity_id] = resolved
```

- [ ] **Step 4: Public API der Federation-Schicht re-exportieren**

Ersetze den Inhalt von `src/fastapi_auth/openid/federation/__init__.py` durch:

```python
"""OpenID Federation 1.0 trust layer (entity statements, trust chains, metadata policy).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.openid.federation.entity_configuration import (
    build_rp_entity_configuration,
    sign_rp_entity_configuration,
)
from fastapi_auth.openid.federation.errors import (
    EntityStatementError,
    FederationError,
    FetchError,
    MetadataPolicyError,
    SignatureError,
    TrustChainError,
)
from fastapi_auth.openid.federation.trust_chain import (
    ResolvedEntity,
    TrustChainCache,
    ValidatedChain,
    resolve_and_validate,
    resolve_metadata,
    resolve_trust_chain,
    validate_trust_chain,
)

__all__ = [
    "EntityStatementError",
    "FederationError",
    "FetchError",
    "MetadataPolicyError",
    "ResolvedEntity",
    "SignatureError",
    "TrustChainCache",
    "TrustChainError",
    "ValidatedChain",
    "build_rp_entity_configuration",
    "resolve_and_validate",
    "resolve_metadata",
    "resolve_trust_chain",
    "sign_rp_entity_configuration",
    "validate_trust_chain",
]
```

- [ ] **Step 5: Test grün laufen lassen**

Run: `uv run pytest tests/federation/test_resolve_and_validate.py -v`
Expected: alle passed.

- [ ] **Step 6: Ganze Suite + Lint**

Run:

```bash
uv run pytest
uv run ruff format .
uv run ruff check .
uv run ty check src tests
make lint
```

Expected: pytest alle passed (Plan-1- + Plan-2-Tests); ruff „All checks passed!"; `ty` ohne Fehler; `make lint` exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/federation/trust_chain.py src/fastapi_auth/openid/federation/__init__.py tests/federation/test_resolve_and_validate.py
git commit -m "feat(federation): resolve_and_validate + Resolved Metadata + Trust-Chain-Cache"
```

---

## Self-Review

**Spec-Abdeckung (Plan 2 vs. Design §2/§3/§6/§7 + Roadmap Plan 2):**
- Entity Statements (build/sign/verify, `typ`, Required Claims, `iat`/`exp`) → Tasks 1–2 ✅
- Eigene RP Entity Configuration (self-signed, `metadata.openid_relying_party`, `authority_hints`) → Task 3 ✅
- Async Fetch (`.well-known` Suffix-Regel, Fetch-Endpoint `sub`-Param, Content-Type) → Task 4 ✅
- In-Memory-Testföderation (TA→IM→Leaf, respx) → Task 4 ✅
- Trust-Chain-Auflösung (`authority_hints` → konfigurierter TA, Loop-Schutz, Pruning) → Task 5 ✅
- Trust-Chain-Validierung (Signaturkette ES[j]↔ES[j+1].jwks, TA-Keys out-of-band, Linkage, Zeit, min-exp) → Task 6 ✅, adversarial getestet (falscher Signer, falsche TA-Keys, Anchor nicht konfiguriert, Linkage-Bruch, expired, Leaf nicht self-issued)
- Metadata Policy (Operator-Reihenfolge, Merge TA→Leaf, Konflikt-/Apply-Fehler, `metadata_policy_crit`) → Task 7 ✅
- Orchestrierung `resolve_and_validate` → validierte OP-Metadaten + exp-Cache → Task 8 ✅

**Bewusst NICHT (dokumentiert):** Trust Marks, Constraints-Enforcement, Explicit Registration, OIDC-Login/authlib/Router/Settings (Plan 3+). Kein stiller Skip — als YAGNI/Folgeplan markiert.

**Platzhalter-Scan:** kein TBD/TODO; jeder Code-Schritt enthält vollständigen, lauffähigen Code (joserfc-API verifiziert an v1.7.4) und exakte Kommandos mit erwarteter Ausgabe.

**Typ-Konsistenz:** `jose.sign_entity_statement`/`verify_signature`/`peek_claims`/`peek_header` (T1) ⇄ `entity_statement.verify_statement`/`check_structure`/`check_time` (T2) ⇄ `entity_configuration.sign_rp_entity_configuration` (T3) ⇄ `fetch.fetch_entity_configuration`/`fetch_subordinate_statement` (T4) ⇄ `trust_chain.resolve_trust_chain` (T5) ⇄ `validate_trust_chain`/`ValidatedChain` (T6) ⇄ `metadata_policy.merge_policies`/`apply_policy` (T7) ⇄ `resolve_and_validate`/`ResolvedEntity`/`resolve_metadata`/`TrustChainCache` (T8). `ValidatedChain`-Felder (`statements`, `leaf`, `subordinate_statements`, `trust_anchor_id`, `exp`) werden in T8 konsistent konsumiert. Der `conftest.py`-Testhelfer (T4) wird von T5/T6/T8 wiederverwendet (`federation`/`mock_router`-Fixtures, `subordinate(...)`, `trust_anchor_keys(...)`, `mount`/`mount_fetch`).

**Sicherheits-Selbstprüfung:** Algorithmen überall gepinnt; `peek_*` nur zur Navigation, jede vertrauensrelevante Aussage über `jwt.decode`/`verify_statement`; Anchor MUSS konfiguriert sein (T6 verifiziert Ablehnung sonst); Zeitprüfung mit Skew; Merge-Konflikte und Apply-Verletzungen invalidieren die Kette.

---

## Nächster Meilenstein

- **Plan 3 — OIDC-Login:** authlib-Client (Auth-Code+PKCE, Token, ID-Token-Validierung gegen die aus
  `resolve_and_validate` gewonnenen OP-JWKS) + automatic client registration (RP-`entity_id` als
  `client_id`, `private_key_jwt` mit den Fed-Keys) + Router (`/openid/login`, `/openid/callback`,
  `/.well-known/openid-federation` via `sign_rp_entity_configuration`) + `settings.py` (Entity/Keys,
  Trust Anchors, `authority_hints`).
