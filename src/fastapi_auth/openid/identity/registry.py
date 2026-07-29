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
