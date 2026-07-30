"""Tests for the signed-cookie session backend."""

from typing import Any

import pytest
from fastapi import Request, Response

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.cookie import CookieBackend
from fastapi_auth.openid.session.store import MemoryStore
from fastapi_auth.openid.settings import OidcSettings

_JWKS: dict[str, Any] = {"keys": []}


def _settings(**over) -> OidcSettings:
    base: dict[str, Any] = dict(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks=_JWKS,
        session_secret="s" * 32,
    )
    base.update(over)
    return OidcSettings(**base)


def _request_with_cookie(name: str, value: str) -> Request:
    cookie_bytes = f"{name}={value}".encode()
    scope = {"type": "http", "headers": [(b"cookie", cookie_bytes)]}
    return Request(scope)


@pytest.mark.asyncio
async def test_establish_sets_cookie_and_stores_identity():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    identity = FederatedIdentity(sub="u1", mail=["u@lmu.de"])
    await backend.establish(identity, response)
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()


@pytest.mark.asyncio
async def test_round_trip_load_returns_identity():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    cookie_name = settings.session_cookie_name
    cookie_value = _extract_cookie_value(response, cookie_name)
    request = _request_with_cookie(cookie_name, cookie_value)
    loaded = await backend.load(request)
    assert loaded is not None
    assert loaded.sub == "u1"


@pytest.mark.asyncio
async def test_tampered_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = _request_with_cookie(settings.session_cookie_name, "not-a-valid-signed-value")
    assert await backend.load(request) is None


@pytest.mark.asyncio
async def test_missing_cookie_returns_none():
    settings = _settings()
    backend = CookieBackend(settings, MemoryStore())
    request = Request({"type": "http", "headers": []})
    assert await backend.load(request) is None


@pytest.mark.asyncio
async def test_revoke_deletes_store_and_cookie():
    settings = _settings()
    store = MemoryStore()
    backend = CookieBackend(settings, store)
    response = Response()
    await backend.establish(FederatedIdentity(sub="u1"), response)
    cookie_name = settings.session_cookie_name
    cookie_value = _extract_cookie_value(response, cookie_name)
    request = _request_with_cookie(cookie_name, cookie_value)
    revoke_response = Response()
    await backend.revoke(request, revoke_response)
    assert await backend.load(request) is None
    set_cookie_lower = revoke_response.headers["set-cookie"].lower()
    has_max_age_zero = "max-age=0" in set_cookie_lower
    has_expires = "expires" in set_cookie_lower
    assert has_max_age_zero or has_expires


def _extract_cookie_value(response: Response, name: str) -> str:
    raw = response.headers["set-cookie"]
    # "<name>=<value>; Path=/; ..."
    pair = raw.split(";", 1)[0]
    return pair.split("=", 1)[1]
