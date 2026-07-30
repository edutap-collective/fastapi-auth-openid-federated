"""ID-token validation against OP keys obtained from the federation trust chain.

Mirrors ``federation.entity_statement.verify_statement``: verify the JWS
signature with the OP's protocol JWKS (resolved via the trust chain), then run
explicit OIDC claim checks (iss, aud/azp, nonce, exp/iat). The signature keys
are the ones the trust chain validated — never fetched from unauthenticated
discovery.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import SignatureError
from fastapi_auth.openid.oidc.errors import IdTokenError


def validate_id_token(
    id_token: str,
    *,
    op_jwks: dict[str, object],
    issuer: str,
    client_id: str,
    nonce: str,
    algorithms: Sequence[str],
    leeway: int = 60,
    now: int | None = None,
) -> dict[str, object]:
    """Verify the ID token's signature and validate its claims."""
    keyset = jose.load_keyset(op_jwks)
    try:
        claims = jose.verify_signature(id_token, keyset, algorithms=algorithms)
    except SignatureError as exc:
        raise IdTokenError(f"id_token signature invalid: {exc}") from exc

    if claims.get("iss") != issuer:
        raise IdTokenError(f"id_token iss {claims.get('iss')!r} != expected {issuer!r}")

    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in audiences:
        raise IdTokenError(f"id_token aud does not include client_id {client_id!r}")
    if len(audiences) > 1 and claims.get("azp") != client_id:
        raise IdTokenError("id_token has multiple aud but azp != client_id")

    if claims.get("nonce") != nonce:
        raise IdTokenError("id_token nonce does not match the login request")

    moment = jose.now_epoch() if now is None else now
    exp = claims.get("exp")
    iat = claims.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        raise IdTokenError("id_token has non-integer iat/exp")
    if exp < moment - leeway:
        raise IdTokenError("id_token is expired")
    if iat > moment + leeway:
        raise IdTokenError("id_token iat is in the future")

    return claims
