"""Tests for the joserfc JWT backend with an asymmetric jwt_alg."""

from typing import cast

import pytest
from fastapi import Request, Response
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.settings import OidcSettings


def _bearer_request(token: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})


def _settings(jwks_private: dict) -> OidcSettings:
    return OidcSettings(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks={"keys": []},
        backend="jwt",
        jwt_alg="RS256",
        jwt_jwks=jwks_private,
    )


@pytest.mark.asyncio
async def test_asymmetric_round_trip():
    key = RSAKey.generate_key(key_size=2048, parameters={"kid": "sess-1"}, private=True)
    private_jwks = cast(dict[str, object], KeySet([key]).as_dict(private=True))
    backend = JWTBackend(_settings(private_jwks))
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", eppn="u1@lmu.de"), response)
    token = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.eppn == "u1@lmu.de"
