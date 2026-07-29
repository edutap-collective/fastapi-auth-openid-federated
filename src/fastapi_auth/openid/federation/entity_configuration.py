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
