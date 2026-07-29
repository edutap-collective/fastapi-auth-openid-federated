"""Map an OIDC claims dict (id_token + userinfo) onto FederatedIdentity.

Pure function — no OIDC/JOSE/network. The caller (OIDC layer, later milestone)
passes the merged, validated claims.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi_auth.openid.identity import registry
from fastapi_auth.openid.identity.model import FederatedIdentity


def _coerce(value: object, *, multivalued: bool) -> object:
    if multivalued:
        return list(value) if isinstance(value, list) else [value]
    return value[0] if isinstance(value, list) and value else value


def map_claims(claims: Mapping[str, object]) -> FederatedIdentity:
    """Build a FederatedIdentity from a claims dict; keep all claims."""
    fields: dict[str, object] = {}
    for name, value in claims.items():
        if value is None:
            continue
        definition = registry.resolve(name)
        if definition is None:
            continue
        coerced_value = _coerce(value, multivalued=definition.multivalued)
        fields[definition.field] = coerced_value

    return FederatedIdentity(
        claims=dict(claims),
        **fields,  # type: ignore
    )
