"""Login orchestration: begin_login (authorization redirect) and complete_login.

Ties the federation trust layer (Plan 2) to the OIDC client pieces: resolve and
validate the OP's metadata, build a PKCE + signed request object authorization
redirect, then on callback exchange the code (private_key_jwt) and validate the
id_token against the OP keys the trust chain produced, mapping claims to a
``FederatedIdentity``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlencode

import httpx
from joserfc.jwk import Key

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.trust_chain import resolve_and_validate
from fastapi_auth.openid.identity.mapper import map_claims
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.login_state import LoginState, LoginStateStore
from fastapi_auth.openid.oidc import id_token as idt
from fastapi_auth.openid.oidc import pkce, request_object, token
from fastapi_auth.openid.oidc.errors import AuthorizationError
from fastapi_auth.openid.settings import OidcSettings


@dataclass(frozen=True)
class AuthorizationRedirect:
    """The OP authorization URL to redirect the browser to, plus its state."""

    url: str
    state: str


def _authorization_url(endpoint: str, *, client_id: str, scope: list[str], request_jwt: str) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(scope),
            "request": request_jwt,
        }
    )
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{query}"


def _op_provider_metadata(metadata: dict[str, object]) -> dict[str, object]:
    provider = metadata
    if not isinstance(provider, dict) or "issuer" not in provider:
        raise AuthorizationError("resolved OP metadata is missing issuer/endpoints")
    return provider


async def begin_login(
    *,
    http_client: httpx.AsyncClient,
    settings: OidcSettings,
    fed_signing_key: object,
    op_entity_id: str,
    next_url: str,
    state_store: LoginStateStore,
    now: int | None = None,
) -> AuthorizationRedirect:
    """Resolve the OP, build the PKCE + request-object redirect, store login state."""
    resolved = await resolve_and_validate(
        http_client,
        op_entity_id,
        settings.trust_anchors,
        entity_type="openid_provider",
        leeway=settings.clock_skew,
        now=now,
    )
    provider = _op_provider_metadata(resolved.metadata)
    authorization_endpoint = provider.get("authorization_endpoint")
    if not isinstance(authorization_endpoint, str):
        raise AuthorizationError("resolved OP metadata is missing authorization_endpoint")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = pkce.create_code_verifier()
    challenge = pkce.code_challenge_s256(verifier)

    claims = request_object.build_request_object(
        client_id=settings.entity_id,
        op_entity_id=op_entity_id,
        redirect_uri=settings.callback_url,
        scope=settings.scopes,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
        lifetime=settings.request_object_lifetime,
        now=now,
    )
    request_jwt = request_object.sign_request_object(claims, cast(Key, fed_signing_key))

    state_store.put(
        LoginState(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            op_entity_id=op_entity_id,
            next_url=next_url,
            op_metadata=provider,
            created=jose.now_epoch() if now is None else now,
        )
    )
    url = _authorization_url(
        authorization_endpoint,
        client_id=settings.entity_id,
        scope=settings.scopes,
        request_jwt=request_jwt,
    )
    return AuthorizationRedirect(url=url, state=state)


async def complete_login(
    *,
    http_client: httpx.AsyncClient,
    settings: OidcSettings,
    fed_signing_key: object,
    login_state: LoginState,
    code: str,
    now: int | None = None,
) -> FederatedIdentity:
    """Exchange the code, validate the id_token, and map claims to an identity."""
    provider = login_state.op_metadata
    token_endpoint = provider.get("token_endpoint")
    op_jwks = provider.get("jwks")
    issuer = provider.get("issuer")
    metadata_complete = (
        isinstance(token_endpoint, str) and isinstance(op_jwks, dict) and isinstance(issuer, str)
    )
    if not metadata_complete:
        raise AuthorizationError("stored OP metadata is incomplete")

    assertion = token.sign_client_assertion(
        token.build_client_assertion(
            client_id=settings.entity_id,
            op_entity_id=login_state.op_entity_id,
            lifetime=settings.client_assertion_lifetime,
            now=now,
        ),
        cast(Key, fed_signing_key),
    )
    tokens = await token.exchange_code(
        http_client,
        token_endpoint=token_endpoint,
        code=code,
        redirect_uri=settings.callback_url,
        code_verifier=login_state.code_verifier,
        client_id=settings.entity_id,
        client_assertion=assertion,
    )

    id_claims = idt.validate_id_token(
        str(tokens["id_token"]),
        op_jwks=cast("dict[str, object]", op_jwks),
        issuer=issuer,
        client_id=settings.entity_id,
        nonce=login_state.nonce,
        algorithms=settings.id_token_signing_alg_values,
        leeway=settings.clock_skew,
        now=now,
    )

    claims: dict[str, object] = dict(id_claims)
    if settings.fetch_userinfo:
        userinfo_endpoint = provider.get("userinfo_endpoint")
        access_token = tokens.get("access_token")
        if isinstance(userinfo_endpoint, str) and isinstance(access_token, str):
            userinfo = await token.fetch_userinfo(
                http_client, userinfo_endpoint=userinfo_endpoint, access_token=access_token
            )
            claims.update(userinfo)

    return map_claims(claims)
