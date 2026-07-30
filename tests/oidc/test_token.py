"""Tests for client-assertion signing, token exchange and userinfo."""

import httpx
import pytest
import respx
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import token
from fastapi_auth.openid.oidc.errors import TokenExchangeError

NOW = 1_700_000_000


def _key(kid: str = "rp-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_client_assertion_aud_is_op_entity_id():
    claims = token.build_client_assertion(
        client_id="https://rp.example", op_entity_id="https://op.example", now=NOW, jti="j1"
    )
    assert claims["iss"] == claims["sub"] == "https://rp.example"
    assert claims["aud"] == "https://op.example"  # NOT the token endpoint URL
    assert claims["exp"] == NOW + 60


def test_sign_client_assertion_verifies():
    key = _key()
    ca = token.sign_client_assertion(
        token.build_client_assertion(
            client_id="https://rp.example", op_entity_id="https://op.example", now=NOW, jti="j1"
        ),
        key,
    )
    assert (
        jose.verify_signature(ca, KeySet([key]), algorithms=["RS256"])["aud"]
        == "https://op.example"
    )


@pytest.mark.asyncio
async def test_exchange_code_posts_expected_form_and_returns_tokens():
    with respx.mock:
        route = respx.post("https://op.example/token").respond(
            200, json={"access_token": "at", "id_token": "idt", "token_type": "Bearer"}
        )
        async with httpx.AsyncClient() as client:
            tokens = await token.exchange_code(
                client,
                token_endpoint="https://op.example/token",  # noqa: S106
                code="c",
                redirect_uri="https://rp.example/openid/callback",
                code_verifier="v",
                client_id="https://rp.example",
                client_assertion="ca.jwt",
            )
    assert tokens["id_token"] == "idt"  # noqa: S105
    form = dict(httpx.QueryParams(route.calls.last.request.content.decode()))
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "c"
    assert form["code_verifier"] == "v"
    assert form["client_id"] == "https://rp.example"
    assert form["client_assertion"] == "ca.jwt"
    assert form["client_assertion_type"] == token.CLIENT_ASSERTION_TYPE


@pytest.mark.asyncio
async def test_exchange_code_error_body_raises():
    with respx.mock:
        respx.post("https://op.example/token").respond(400, json={"error": "invalid_grant"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(TokenExchangeError, match="invalid_grant"):
                await token.exchange_code(
                    client,
                    token_endpoint="https://op.example/token",  # noqa: S106
                    code="c",
                    redirect_uri="https://rp.example/openid/callback",
                    code_verifier="v",
                    client_id="https://rp.example",
                    client_assertion="ca.jwt",
                )


@pytest.mark.asyncio
async def test_exchange_code_missing_id_token_raises():
    with respx.mock:
        respx.post("https://op.example/token").respond(200, json={"access_token": "at"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(TokenExchangeError, match="id_token"):
                await token.exchange_code(
                    client,
                    token_endpoint="https://op.example/token",  # noqa: S106
                    code="c",
                    redirect_uri="https://rp.example/openid/callback",
                    code_verifier="v",
                    client_id="https://rp.example",
                    client_assertion="ca.jwt",
                )


@pytest.mark.asyncio
async def test_fetch_userinfo_sends_bearer():
    with respx.mock:
        route = respx.get("https://op.example/userinfo").respond(
            200, json={"sub": "u", "email": "u@x"}
        )
        async with httpx.AsyncClient() as client:
            claims = await token.fetch_userinfo(
                client,
                userinfo_endpoint="https://op.example/userinfo",
                access_token="at",  # noqa: S106
            )
    assert claims["email"] == "u@x"
    assert route.calls.last.request.headers["authorization"] == "Bearer at"
