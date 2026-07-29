# Plan 1 — Fundament & Identität (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Package-Fundament (`fastapi_auth.openid`-Namespace, Tooling) und das
Identitäts-Herzstück (Claim-Registry, `FederatedIdentity`, Claim-Mapper, Identifier-Auswahl)
als reine, unit-getestete Bibliotheksschicht ohne Netzwerk aufbauen.

**Architecture:** PEP-420-Namespace-Package `fastapi_auth` (src-Layout, kein `__init__.py`
in `fastapi_auth/`) mit dem Submodul `openid`. Die `identity/`-Schicht ist eigenständig: Eine
deklarative Registry mappt OIDC-Claim-Namen (Standard-OIDC + eduPerson-via-OIDC) auf Felder
eines Pydantic-v2-Modells; ein reiner Mapper übersetzt ein Claims-Dict (aus `id_token`+`userinfo`)
in `FederatedIdentity`. Keine OIDC-/JOSE-/HTTP-Abhängigkeit in diesem Meilenstein.

**Tech Stack:** Python 3.12+, setuptools (PEP 420 namespaces), Pydantic v2, pydantic-settings,
pytest, ruff, ty, uv.

## Global Constraints

- Distribution (PyPI): `fastapi-auth-openid-federated`; Import: `from fastapi_auth import openid`.
- Namespace `fastapi_auth` ist PEP-420-implizit — **niemals** `src/fastapi_auth/__init__.py` anlegen.
- Lizenz: `Apache-2.0 OR EUPL-1.2` (SPDX-Ausdruck); Dual-License-Header in Quellcodedateien.
- Python-Floor: `>=3.12`. async-first (spätere Meilensteine); hier reiner sync-freier Code.
- Sprache: Code/Kommentare/Docstrings **Englisch**; Commit-Messages **Deutsch** (LMU-Kontext), Conventional Commits.
- Feld-Ausrichtung: `FederatedIdentity` nutzt für überlappende Attribute **dieselben Feldnamen wie das SAML-Package** (`eppn`, `scoped_affiliation`, `affiliation`, `entitlement`, `assurance`, `mail`, `display_name`, `given_name`, `surname`, `home_organization`, `preferred_language`), damit Consumer beide Packages einheitlich nutzen.
- Typisierung: Type Hints für alle öffentlichen Funktionen; kein `Any` ohne Begründung.
- ruff-Regelgruppen: `E,F,W,B,UP,I,D,S`. Tests dürfen `S101`/`D` ignorieren.
- Niemals `git push`; niemals direkt auf `main` — Arbeit läuft auf `main` NUR wenn ausdrücklich erlaubt, sonst `feature/…`-Branch. (Für dieses neue Repo: Commits auf `main` sind ok — leeres Repo, vom Nutzer so gewünscht.)
- Autor: `Alexander Loechel <Alexander.Loechel@lmu.de>` (im Repo lokal konfiguriert).

## File Structure

```text
pyproject.toml                          # Distribution, Deps, ruff/pytest/ty-Konfig
Makefile                                # lint / reformat / test-local
LICENSE-APACHE                          # Apache-2.0 Volltext
LICENSE-EUPL                            # EUPL-1.2 Volltext
.python-version                         # 3.12
src/fastapi_auth/openid/__init__.py     # Public API (Re-Exports der identity-Schicht)
src/fastapi_auth/openid/py.typed        # PEP 561 Marker (leer)
src/fastapi_auth/openid/identity/__init__.py
src/fastapi_auth/openid/identity/registry.py   # ClaimDef + REGISTRY + Resolver
src/fastapi_auth/openid/identity/model.py      # FederatedIdentity (Pydantic v2)
src/fastapi_auth/openid/identity/mapper.py     # map_claims(): dict -> FederatedIdentity
src/fastapi_auth/openid/identity/identifier.py # select_identifier()
tests/test_scaffold.py
tests/identity/test_registry.py
tests/identity/test_model.py
tests/identity/test_mapper.py
tests/identity/test_identifier.py
```

---

## Task 1: Projekt-Gerüst & Tooling

**Files:**
- Create: `pyproject.toml`, `Makefile`, `.python-version`, `LICENSE-APACHE`, `LICENSE-EUPL`
- Create: `src/fastapi_auth/openid/__init__.py`, `src/fastapi_auth/openid/py.typed`
- Modify: `README.md` (bereits vorhanden — Install-Notiz ergänzen)
- Test: `tests/test_scaffold.py`

**Interfaces:**
- Consumes: nichts.
- Produces: importierbares Package `fastapi_auth.openid` (`openid.__version__: str`); lauffähiges `uv run pytest`, `uv run ruff check`.

- [ ] **Step 1: `.python-version` anlegen**

```text
3.12
```

- [ ] **Step 2: `pyproject.toml` anlegen**

```toml
[build-system]
requires = ["setuptools>=77.0.0"]
build-backend = "setuptools.build_meta"

[project]
name = "fastapi-auth-openid-federated"
version = "0.1.0.dev0"
description = "Federated OpenID Connect Relying Party for FastAPI (OpenID Federation 1.0)"
readme = "README.md"
requires-python = ">=3.12"
license = "Apache-2.0 OR EUPL-1.2"
license-files = ["LICENSE-APACHE", "LICENSE-EUPL"]
authors = [{ name = "Alexander Loechel", email = "Alexander.Loechel@lmu.de" }]
keywords = ["openid", "oidc", "openid-federation", "fastapi", "sso", "federation", "eduperson"]
classifiers = [
    "Framework :: FastAPI",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: System :: Systems Administration :: Authentication/Directory",
]
dependencies = [
    "fastapi>=0.115",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.23",
    "anyio>=4",
    "respx>=0.21",
    "httpx>=0.27",
    "ruff>=0.6",
    "ty",
    "pdbp>=1.5",
]

[project.urls]
Repository = "https://github.com/edutap-collective/fastapi-auth-openid-federated"

[tool.setuptools.packages.find]
where = ["src"]
include = ["fastapi_auth*"]
namespaces = true

[tool.ruff]
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "W", "B", "UP", "I", "D", "S"]
ignore = ["D203", "D213"]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101", "D"]

[tool.ruff.lint.pydocstyle]
convention = "pep257"

[tool.pytest.ini_options]
addopts = "-ra"
testpaths = ["tests"]
asyncio_mode = "auto"
pythonpath = ["."]
```

- [ ] **Step 3: Lizenz-Volltexte anlegen**

Run:

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE-APACHE
curl -fsSL "https://joinup.ec.europa.eu/sites/default/files/custom-page/attachment/2020-03/EUPL-1.2%20EN.txt" -o LICENSE-EUPL
grep -qi 'Apache License' LICENSE-APACHE && grep -qi 'European Union Public Licence' LICENSE-EUPL && echo "licenses ok"
```

Expected: `licenses ok`. VERIFY the content, not just the byte count — `LICENSE-EUPL` must be plain license text (`European Union Public Licence`), NOT an HTML page (`<!DOCTYPE`). If the URL fails, fetch the EUPL-1.2 English plain text from <https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12>. If both fail, report NEEDS_CONTEXT — do NOT commit a stub.

- [ ] **Step 4: `Makefile` anlegen**

```make
.PHONY: install lint reformat test-local test-integration

install:
	uv pip install -U -e ".[dev]"

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run ty check src tests

reformat:
	uv run ruff format .
	uv run ruff check --fix .

test-local:
	uv run pytest

test-integration:
	@echo "Integrationstests kommen in einem spaeteren Meilenstein (compose)."
```

- [ ] **Step 5: Namespace-Package anlegen (KEIN `__init__.py` in `fastapi_auth/`)**

Run:

```bash
mkdir -p src/fastapi_auth/openid
touch src/fastapi_auth/openid/py.typed
test ! -e src/fastapi_auth/__init__.py && echo "namespace ok"
```

Expected: `namespace ok`

`src/fastapi_auth/openid/__init__.py`:

```python
"""Federated OpenID Connect Relying Party for FastAPI.

Public entry point of the ``fastapi_auth.openid`` package.
Import via ``from fastapi_auth import openid``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0.dev0"
```

- [ ] **Step 6: `README.md` um Install-/Lizenz-Notiz ergänzen**

Ersetze den gesamten Inhalt von `README.md` durch:

````markdown
# fastapi-auth-openid-federated

Federated OpenID Connect Relying Party for FastAPI — trust via OpenID Federation 1.0.
Part of the `fastapi_auth` package family.

```python
from fastapi_auth import openid
```

## Install (development)

```bash
uv venv && source .venv/bin/activate
make install          # uv pip install -U -e ".[dev]"
make test-local
```

## License

Dual-licensed: **Apache-2.0 OR EUPL-1.2** — the recipient may choose either.
See `LICENSE-APACHE` and `LICENSE-EUPL`.
````

- [ ] **Step 7: Scaffold-Test schreiben (failing)**

`tests/test_scaffold.py`:

```python
"""Smoke tests for the package scaffold and namespace layout."""

import fastapi_auth.openid as openid


def test_package_imports_via_namespace():
    assert openid.__version__ == "0.1.0.dev0"


def test_namespace_has_no_init_module():
    import fastapi_auth

    # PEP 420 namespace packages expose no single __file__.
    assert getattr(fastapi_auth, "__file__", None) is None
```

- [ ] **Step 8: Env erstellen & Test laufen lassen (rot → grün)**

Run:

```bash
uv venv
uv pip install -U -e ".[dev]"
uv run pytest tests/test_scaffold.py -v
```

Expected: 2 passed. (Falls `fastapi_auth.__file__` gesetzt ist, wurde versehentlich ein `__init__.py` erzeugt — löschen.)

- [ ] **Step 9: Lint & Format prüfen**

Run: `uv run ruff format . && uv run ruff check .`
Expected: „All checks passed!" und keine Format-Änderungen offen.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml Makefile .python-version LICENSE-APACHE LICENSE-EUPL README.md src tests/test_scaffold.py
git commit -m "chore: Projekt-Gerüst mit fastapi_auth.openid-Namespace und Tooling"
```

---

## Task 2: Claim-Registry (OIDC + eduPerson-via-OIDC)

**Files:**
- Create: `src/fastapi_auth/openid/identity/__init__.py`, `src/fastapi_auth/openid/identity/registry.py`
- Test: `tests/identity/test_registry.py`

**Interfaces:**
- Consumes: nichts.
- Produces:
  - `ClaimDef` (frozen dataclass): Felder `field: str`, `claim: str`, `multivalued: bool`.
  - `REGISTRY: tuple[ClaimDef, ...]`.
  - `resolve(claim: str) -> ClaimDef | None` — Lookup nach OIDC-Claim-Name.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_registry.py`:

```python
"""Tests for the OIDC/eduPerson claim registry."""

import pytest

from fastapi_auth.openid.identity import registry


def test_resolve_standard_claim():
    d = registry.resolve("email")
    assert d is not None
    assert d.field == "mail"
    assert d.multivalued is True


def test_resolve_sub_and_iss():
    assert registry.resolve("sub").field == "sub"
    assert registry.resolve("iss").field == "iss"


def test_resolve_eduperson_claims():
    assert registry.resolve("eduperson_principal_name").field == "eppn"
    assert registry.resolve("eduperson_scoped_affiliation").field == "scoped_affiliation"
    assert registry.resolve("eduperson_scoped_affiliation").multivalued is True


def test_resolve_schac():
    assert registry.resolve("schac_home_organization").field == "home_organization"


def test_unknown_returns_none():
    assert registry.resolve("no_such_claim") is None


@pytest.mark.parametrize("field", ["sub", "iss", "eppn", "mail", "scoped_affiliation", "home_organization"])
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_registry.py -v`
Expected: FAIL (`ModuleNotFoundError: fastapi_auth.openid.identity`).

- [ ] **Step 3: `identity`-Package + Registry implementieren**

`src/fastapi_auth/openid/identity/__init__.py`:

```python
"""Identity layer: claim registry, model, mapper, identifier selection.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""
```

`src/fastapi_auth/openid/identity/registry.py`:

```python
"""Registry mapping OIDC/eduPerson claim names to FederatedIdentity fields.

Covers standard OpenID Connect claims and the eduPerson/SCHAC-over-OIDC claims
(REFEDS "OIDCre"). ``multivalued`` reflects whether the TARGET field is a list;
the mapper coerces a scalar claim into a single-element list where needed.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClaimDef:
    """A single known claim and how it maps onto FederatedIdentity."""

    field: str
    claim: str
    multivalued: bool


REGISTRY: tuple[ClaimDef, ...] = (
    # --- identifiers ---
    ClaimDef("sub", "sub", False),
    ClaimDef("iss", "iss", False),
    # --- standard OIDC profile / email ---
    ClaimDef("mail", "email", True),
    ClaimDef("email_verified", "email_verified", False),
    ClaimDef("display_name", "name", False),
    ClaimDef("given_name", "given_name", False),
    ClaimDef("surname", "family_name", False),
    ClaimDef("preferred_username", "preferred_username", False),
    ClaimDef("preferred_language", "locale", False),
    ClaimDef("picture", "picture", False),
    # --- authentication context ---
    ClaimDef("acr", "acr", False),
    ClaimDef("amr", "amr", True),
    ClaimDef("auth_time", "auth_time", False),
    # --- eduPerson / SCHAC over OIDC (REFEDS OIDCre) ---
    ClaimDef("eppn", "eduperson_principal_name", False),
    ClaimDef("scoped_affiliation", "eduperson_scoped_affiliation", True),
    ClaimDef("affiliation", "eduperson_affiliation", True),
    ClaimDef("entitlement", "eduperson_entitlement", True),
    ClaimDef("assurance", "eduperson_assurance", True),
    ClaimDef("home_organization", "schac_home_organization", False),
)

_BY_CLAIM: dict[str, ClaimDef] = {d.claim: d for d in REGISTRY}


def resolve(claim: str) -> ClaimDef | None:
    """Resolve a claim definition by its OIDC claim name."""
    return _BY_CLAIM.get(claim)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_registry.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/identity/__init__.py src/fastapi_auth/openid/identity/registry.py tests/identity/test_registry.py
git commit -m "feat(identity): Claim-Registry für OIDC + eduPerson-via-OIDC"
```

---

## Task 3: `FederatedIdentity`-Modell

**Files:**
- Create: `src/fastapi_auth/openid/identity/model.py`
- Test: `tests/identity/test_model.py`

**Interfaces:**
- Consumes: nichts (rein deklarativ).
- Produces: `FederatedIdentity` (Pydantic `BaseModel`) mit den Feldern:
  - Single (`str | None`): `sub, iss, eppn, home_organization, display_name, given_name, surname, preferred_username, preferred_language, picture, acr`
  - `email_verified: bool | None`, `auth_time: int | None`
  - Multi (`list[str]`, default `[]`): `mail, affiliation, scoped_affiliation, entitlement, assurance, amr`
  - Escape-Hatch: `claims: dict[str, object]` (default `{}`)
  - Alle Defaults gesetzt, sodass `FederatedIdentity()` konstruiert werden kann.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_model.py`:

```python
"""Tests for the FederatedIdentity model."""

from fastapi_auth.openid.identity.model import FederatedIdentity


def test_empty_identity_has_sane_defaults():
    ident = FederatedIdentity()
    assert ident.sub is None
    assert ident.mail == []
    assert ident.scoped_affiliation == []
    assert ident.claims == {}


def test_identity_holds_values():
    ident = FederatedIdentity(
        sub="u123",
        iss="https://op.example",
        eppn="u123@lmu.de",
        scoped_affiliation=["staff@lmu.de", "member@lmu.de"],
        mail=["a@lmu.de"],
        email_verified=True,
        claims={"email": "a@lmu.de"},
    )
    assert ident.sub == "u123"
    assert ident.eppn == "u123@lmu.de"
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]
    assert ident.email_verified is True
    assert ident.claims["email"] == "a@lmu.de"


def test_multivalue_lists_are_independent_between_instances():
    a = FederatedIdentity()
    a.mail.append("x@lmu.de")
    b = FederatedIdentity()
    assert b.mail == []
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_model.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Modell implementieren**

`src/fastapi_auth/openid/identity/model.py`:

```python
"""Typed identity assembled from OIDC claims.

Well-known claims are typed fields; the full set of received claims (id_token +
userinfo) is always available under ``claims``. Overlapping field names match the
SAML package's FederatedIdentity so consumers can use both uniformly.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FederatedIdentity(BaseModel):
    """Curated view of the claims released by an OpenID Provider."""

    # --- stable identifiers ---
    sub: str | None = None
    iss: str | None = None
    eppn: str | None = None

    # --- affiliation / authorization ---
    affiliation: list[str] = Field(default_factory=list)
    scoped_affiliation: list[str] = Field(default_factory=list)
    entitlement: list[str] = Field(default_factory=list)
    assurance: list[str] = Field(default_factory=list)

    # --- personal / core ---
    mail: list[str] = Field(default_factory=list)
    email_verified: bool | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    preferred_username: str | None = None
    preferred_language: str | None = None
    picture: str | None = None

    # --- organization ---
    home_organization: str | None = None

    # --- authentication context ---
    acr: str | None = None
    amr: list[str] = Field(default_factory=list)
    auth_time: int | None = None

    # --- escape hatch: all received claims (claim-name -> value) ---
    claims: dict[str, object] = Field(default_factory=dict)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_model.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/identity/model.py tests/identity/test_model.py
git commit -m "feat(identity): FederatedIdentity-Modell (OIDC-Claims + Escape-Hatch)"
```

---

## Task 4: Claim-Mapper

**Files:**
- Create: `src/fastapi_auth/openid/identity/mapper.py`
- Test: `tests/identity/test_mapper.py`

**Interfaces:**
- Consumes: `registry.resolve` (Task 2), `FederatedIdentity` (Task 3).
- Produces:
  - `map_claims(claims: dict[str, object]) -> FederatedIdentity`
  - Verhalten: für jeden Claim, den die Registry kennt, das Zielfeld setzen. **Coercion:** ist das Zielfeld multi (`list`) und der Wert skalar → in `[value]` wrappen; ist es multi und der Wert bereits eine Liste → übernehmen; ist es single und der Wert eine Liste → ersten Wert. `None`-Werte werden übersprungen. `claims` enthält **alle** übergebenen Claims (roh). Unbekannte Claims landen nur in `claims`.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_mapper.py`:

```python
"""Tests for mapping a claims dict onto FederatedIdentity."""

from fastapi_auth.openid.identity.mapper import map_claims


def test_scalar_claim_maps():
    ident = map_claims({"sub": "u123", "iss": "https://op.example"})
    assert ident.sub == "u123"
    assert ident.iss == "https://op.example"


def test_scalar_email_coerced_to_list():
    ident = map_claims({"email": "a@lmu.de", "email_verified": True})
    assert ident.mail == ["a@lmu.de"]
    assert ident.email_verified is True


def test_list_claim_kept_as_list():
    ident = map_claims({"eduperson_scoped_affiliation": ["staff@lmu.de", "member@lmu.de"]})
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]


def test_eduperson_principal_name_maps_to_eppn():
    assert map_claims({"eduperson_principal_name": "u@lmu.de"}).eppn == "u@lmu.de"


def test_claims_escape_hatch_holds_all_raw_claims():
    raw = {"sub": "u", "email": "a@lmu.de", "custom_claim": "x"}
    ident = map_claims(raw)
    assert ident.claims == raw
    assert ident.claims["custom_claim"] == "x"


def test_none_value_is_skipped():
    ident = map_claims({"sub": None, "email": None})
    assert ident.sub is None
    assert ident.mail == []


def test_auth_time_epoch_int():
    ident = map_claims({"auth_time": 1700000000})
    assert ident.auth_time == 1700000000
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_mapper.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Mapper implementieren**

`src/fastapi_auth/openid/identity/mapper.py`:

```python
"""Map an OIDC claims dict (id_token + userinfo) onto FederatedIdentity.

Pure function — no OIDC/JOSE/network. The caller (OIDC layer, later milestone)
passes the merged, validated claims.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.openid.identity import registry
from fastapi_auth.openid.identity.model import FederatedIdentity


def _coerce(value: object, *, multivalued: bool) -> object:
    if multivalued:
        return list(value) if isinstance(value, list) else [value]
    return value[0] if isinstance(value, list) and value else value


def map_claims(claims: dict[str, object]) -> FederatedIdentity:
    """Build a FederatedIdentity from a claims dict; keep all claims in .claims."""
    fields: dict[str, object] = {}
    for name, value in claims.items():
        if value is None:
            continue
        definition = registry.resolve(name)
        if definition is None:
            continue
        fields[definition.field] = _coerce(value, multivalued=definition.multivalued)

    return FederatedIdentity(claims=dict(claims), **fields)
```

- [ ] **Step 4: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_mapper.py -v`
Expected: alle passed.

- [ ] **Step 5: Commit**

```bash
git add src/fastapi_auth/openid/identity/mapper.py tests/identity/test_mapper.py
git commit -m "feat(identity): Claim-Mapper (dict -> FederatedIdentity)"
```

---

## Task 5: Identifier-Auswahl + Public API

**Files:**
- Create: `src/fastapi_auth/openid/identity/identifier.py`
- Modify: `src/fastapi_auth/openid/__init__.py` (Public-API-Re-Exports)
- Test: `tests/identity/test_identifier.py`

**Interfaces:**
- Consumes: `FederatedIdentity` (Task 3).
- Produces:
  - `select_identifier(identity: FederatedIdentity, primary: str, fallback: Sequence[str] = ()) -> str | None`
  - Wählt den ersten nicht-leeren Wert aus `[primary, *fallback]`; jeder Name ist ein `FederatedIdentity`-Feldname (z. B. `"sub"`, `"eppn"`, `"preferred_username"`). Bei Listenfeldern zählt der erste Wert.
- Re-Exports in `fastapi_auth.openid`: `FederatedIdentity`, `map_claims`, `select_identifier`.

- [ ] **Step 1: Failing test schreiben**

`tests/identity/test_identifier.py`:

```python
"""Tests for stable identifier selection."""

from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity


def test_primary_wins_when_present():
    ident = FederatedIdentity(sub="u123", eppn="u@lmu.de")
    assert select_identifier(ident, "sub", ["eppn"]) == "u123"


def test_falls_back_when_primary_missing():
    ident = FederatedIdentity(eppn="u@lmu.de")
    assert select_identifier(ident, "sub", ["eppn"]) == "u@lmu.de"


def test_returns_none_when_nothing_matches():
    assert select_identifier(FederatedIdentity(), "sub", ["eppn"]) is None


def test_list_field_uses_first_value():
    ident = FederatedIdentity(mail=["first@lmu.de", "second@lmu.de"])
    assert select_identifier(ident, "mail") == "first@lmu.de"


def test_public_api_reexports():
    from fastapi_auth import openid

    assert hasattr(openid, "FederatedIdentity")
    assert hasattr(openid, "map_claims")
    assert hasattr(openid, "select_identifier")
```

- [ ] **Step 2: Test rot laufen lassen**

Run: `uv run pytest tests/identity/test_identifier.py -v`
Expected: FAIL (`ModuleNotFoundError` bzw. fehlende Re-Exports).

- [ ] **Step 3: `select_identifier` implementieren**

`src/fastapi_auth/openid/identity/identifier.py`:

```python
"""Select the stable identifier for a relying party.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.openid.identity.model import FederatedIdentity


def select_identifier(
    identity: FederatedIdentity,
    primary: str,
    fallback: Sequence[str] = (),
) -> str | None:
    """Return the first non-empty identifier field value in preference order.

    Each name is a FederatedIdentity field (e.g. ``"sub"``, ``"eppn"``). For
    list-valued fields the first element is used.
    """
    for name in (primary, *fallback):
        value = getattr(identity, name, None)
        if isinstance(value, list):
            value = value[0] if value else None
        if value:
            return str(value)
    return None
```

- [ ] **Step 4: Public API re-exportieren**

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

__all__ = [
    "FederatedIdentity",
    "__version__",
    "map_claims",
    "select_identifier",
]

__version__ = "0.1.0.dev0"
```

- [ ] **Step 5: Test grün laufen lassen**

Run: `uv run pytest tests/identity/test_identifier.py -v`
Expected: alle passed.

- [ ] **Step 6: Ganze Suite + Lint grün**

Run:

```bash
uv run pytest
uv run ruff format .
uv run ruff check .
uv run ty check src tests
```

Expected: pytest alle passed; ruff „All checks passed!"; `ty` ohne Fehler (bei ty-pre-release-Rauschen: dokumentieren, nicht überpatchen).

- [ ] **Step 7: Commit**

```bash
git add src/fastapi_auth/openid/identity/identifier.py src/fastapi_auth/openid/__init__.py tests/identity/test_identifier.py
git commit -m "feat(identity): Identifier-Auswahl + Public-API-Re-Exports"
```

---

## Self-Review

**Spec-Abdeckung (Plan 1 vs. Spec §1 Familie / §4 Identity):**
- Namespace-Packaging (`fastapi_auth.openid`, PEP 420, kein `__init__.py`) → Task 1 ✅
- Dual-Lizenz `Apache-2.0 OR EUPL-1.2` → Task 1 (pyproject + LICENSE-Dateien) ✅
- Claim-Registry OIDC + eduPerson-via-OIDC → Task 2 ✅
- `FederatedIdentity` typisiert + Escape-Hatch, Feld-Ausrichtung mit SAML → Task 3 ✅
- Claim-Mapper (single/multi-Coercion, alle Claims in `.claims`) → Task 4 ✅
- Identifier-Auswahl (`sub`→`eppn`→…) + Public API → Task 5 ✅
- Tooling ruff/ty/pytest/Make → Task 1 ✅

**Bewusst NICHT in Plan 1 (Folgepläne):** Federation-Entity-Core (Statements/Trust-Chain/Policy,
Plan 2), OIDC-Login via authlib (Plan 3), Session/Store (Plan 4), Discovery/WAYF/Logout (Plan 5),
Docker/CI/Doku (Plan 6). Diese hängen an Netzwerk/JOSE und gehören in Meilenstein 2–6.

**Platzhalter-Scan:** keine TBD/TODO; jeder Code-Schritt enthält vollständigen Code und exakte Kommandos mit erwarteter Ausgabe.

**Typ-Konsistenz:** `ClaimDef.field`-Werte (Task 2) = `FederatedIdentity`-Feldnamen (Task 3) = Mapper-Zuweisungen (Task 4) = Identifier-Feldnamen (Task 5). Geprüft: `sub`, `iss`, `eppn`, `scoped_affiliation`, `mail`, `home_organization`, `email_verified`, `amr`, `auth_time` stimmen überein.

---

## Nächste Meilensteine (eigene Pläne)

- **Plan 2 — Federation-Entity-Core:** Entity Statements (joserfc), Entity Configuration,
  Trust-Chain-Auflösung + Validierung (bis konfiguriertem Trust Anchor), Metadata Policy;
  In-Memory-Testföderation via respx.
- **Plan 3 — OIDC-Login:** authlib-Client (Auth-Code+PKCE, Token, ID-Token via Trust-Chain-JWKS) +
  automatic client registration + Router (`/login`, `/callback`, `/.well-known/openid-federation`).
- **Plan 4 — Session-Backends:** Cookie/JWT(joserfc) + Memory/Redis/Postgres + Factory (gespiegelt).
- **Plan 5 — Discovery/WAYF + Logout.**
- **Plan 6 — Docker/CI/Doku.**
