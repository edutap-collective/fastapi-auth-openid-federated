"""Signed authorization request object (JAR) for automatic registration.

OpenID Federation 1.0 §12.1.1.1 requires the authorization request to prove
control of the RP's federation keys via a signed request object typed
``oauth-authz-req+jwt``. Its ``aud`` is the OP's Entity Identifier only, its
``iss``/``client_id`` are the RP's Entity Identifier, and it MUST NOT carry a
``sub`` claim (which would let it be replayed as a private_key_jwt assertion).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

from joserfc import jwt
from joserfc.jwk import Key
from joserfc.jws import JWSRegistry
from joserfc.registry import HeaderParameter

from fastapi_auth.openid.federation import jose

REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"


def build_request_object(
    *,
    client_id: str,
    op_entity_id: str,
    redirect_uri: str,
    scope: Sequence[str],
    state: str,
    nonce: str,
    code_challenge: str,
    response_type: str = "code",
    lifetime: int = 120,
    now: int | None = None,
    jti: str | None = None,
) -> dict[str, object]:
    """Build the request-object claims (no ``sub``; ``aud`` = OP entity id)."""
    issued = jose.now_epoch() if now is None else now
    return {
        "iss": client_id,
        "aud": op_entity_id,
        "client_id": client_id,
        "jti": jti if jti is not None else secrets.token_urlsafe(16),
        "iat": issued,
        "exp": issued + lifetime,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scope),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }


def sign_request_object(
    claims: dict[str, object],
    key: Key,
    *,
    trust_chain: list[str] | None = None,
) -> str:
    """Sign a request object as an ``oauth-authz-req+jwt`` compact JWS."""
    alg = jose.signing_alg(key)
    header: dict[str, object] = {"alg": alg, "typ": REQUEST_OBJECT_TYP, "kid": key.kid}

    # Create registry that permits trust_chain as a header parameter.
    registry = JWSRegistry(
        header_registry={"trust_chain": HeaderParameter("Trust chain", "list[str]")},
        algorithms=[alg],
    )

    if trust_chain is not None:
        header["trust_chain"] = trust_chain

    return jwt.encode(header, claims, key, registry=registry)
