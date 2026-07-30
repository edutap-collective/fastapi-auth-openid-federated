"""Client assertion (private_key_jwt), token exchange and userinfo.

Client authentication at the token endpoint is ``private_key_jwt`` signed with
the RP's federation key. Per OpenID Federation 1.0 §12.1.1.2 the assertion's
``aud`` MUST be the OP's Entity Identifier — not the token endpoint URL, which
is the plain OIDC default. The token endpoint URL is only the POST target.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

import httpx
from joserfc import jwt
from joserfc.jwk import Key

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc.errors import TokenExchangeError

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def build_client_assertion(
    *,
    client_id: str,
    op_entity_id: str,
    lifetime: int = 60,
    now: int | None = None,
    jti: str | None = None,
) -> dict[str, object]:
    """Build the private_key_jwt client-assertion claims (``aud`` = OP entity id)."""
    issued = jose.now_epoch() if now is None else now
    return {
        "iss": client_id,
        "sub": client_id,
        "aud": op_entity_id,
        "jti": jti if jti is not None else secrets.token_urlsafe(16),
        "iat": issued,
        "exp": issued + lifetime,
    }


def sign_client_assertion(claims: dict[str, object], key: Key) -> str:
    """Sign the client-assertion claims as a compact JWS."""
    alg = jose.signing_alg(key)
    header = {"alg": alg, "typ": "JWT", "kid": key.kid}
    return jwt.encode(header, claims, key, algorithms=[alg])


async def exchange_code(
    client: httpx.AsyncClient,
    *,
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_id: str,
    client_assertion: str,
) -> dict[str, object]:
    """Exchange an authorization code for tokens using private_key_jwt auth."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": client_assertion,
    }
    try:
        response = await client.post(token_endpoint, data=data)
    except httpx.HTTPError as exc:
        raise TokenExchangeError(f"token request to {token_endpoint} failed: {exc}") from exc
    if response.status_code >= 400:
        raise TokenExchangeError(_describe_error(response))
    tokens = response.json()
    if not isinstance(tokens, dict) or "id_token" not in tokens:
        raise TokenExchangeError("token response is missing id_token")
    return tokens


async def fetch_userinfo(
    client: httpx.AsyncClient,
    *,
    userinfo_endpoint: str,
    access_token: str,
) -> dict[str, object]:
    """Fetch userinfo claims with the access token as a bearer credential."""
    try:
        response = await client.get(
            userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise TokenExchangeError(f"userinfo request failed: {exc}") from exc
    claims = response.json()
    if not isinstance(claims, dict):
        raise TokenExchangeError("userinfo response is not a JSON object")
    return claims


def _describe_error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"token endpoint returned HTTP {response.status_code}"
    if isinstance(body, dict) and "error" in body:
        description = body.get("error_description", "")
        return f"token endpoint error: {body['error']} {description}".strip()
    return f"token endpoint returned HTTP {response.status_code}"
