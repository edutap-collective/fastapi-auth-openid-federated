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
