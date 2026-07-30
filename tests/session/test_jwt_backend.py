"""Tests for the stateless joserfc JWT session backend (symmetric)."""

import pytest
from fastapi import Request, Response

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.settings import OidcSettings

_JWKS = {"keys": []}


def _settings(**over) -> OidcSettings:
    base = dict(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks=_JWKS,
        backend="jwt",
        session_secret="s" * 32,
    )
    base.update(over)
    return OidcSettings(**base)  # type: ignore


def _cookie_request(name: str, value: str) -> Request:
    return Request({"type": "http", "headers": [(b"cookie", f"{name}={value}".encode())]})


def _bearer_request(token: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())]})


def _cookie_value(response: Response, name: str) -> str:
    return response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]


@pytest.mark.asyncio
async def test_round_trip_via_cookie():
    settings = _settings()
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", mail=["u@lmu.de"]), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_cookie_request(settings.session_cookie_name, token))
    assert loaded is not None
    assert loaded.sub == "u1"
    assert loaded.mail == ["u@lmu.de"]


@pytest.mark.asyncio
async def test_round_trip_via_bearer():
    settings = _settings()
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.sub == "u1"


@pytest.mark.asyncio
async def test_tampered_token_returns_none():
    backend = JWTBackend(_settings())
    assert await backend.load(_bearer_request("not.a.jwt")) is None


@pytest.mark.asyncio
async def test_wrong_secret_returns_none():
    established = JWTBackend(_settings(session_secret="a" * 32))
    response = Response()
    await established.establish(FederatedIdentity(sub="u1"), response)
    token = _cookie_value(response, established._settings.session_cookie_name)  # noqa: SLF001
    other = JWTBackend(_settings(session_secret="b" * 32))
    assert await other.load(_bearer_request(token)) is None


@pytest.mark.asyncio
async def test_expired_token_returns_none():
    settings = _settings(jwt_ttl=1)
    clock = [1000]
    backend = JWTBackend(settings, clock=lambda: clock[0])
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)  # signed at t=1000, exp=1001
    token = _cookie_value(response, settings.session_cookie_name)
    clock[0] = 100000  # far past exp
    assert await backend.load(_bearer_request(token)) is None


@pytest.mark.asyncio
async def test_jwt_attributes_allowlist_restricts_attrs():
    settings = _settings(jwt_attributes=["sub"])
    backend = JWTBackend(settings)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1", mail=["u@lmu.de"]), response)
    token = _cookie_value(response, settings.session_cookie_name)
    loaded = await backend.load(_bearer_request(token))
    assert loaded is not None
    assert loaded.sub == "u1"
    assert loaded.mail == []  # not carried
