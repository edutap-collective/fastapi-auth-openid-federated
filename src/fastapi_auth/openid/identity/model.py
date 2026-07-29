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
