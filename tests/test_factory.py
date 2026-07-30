"""Tests for store/backend selection."""

from fastapi_auth.openid.factory import make_backend, make_store
from fastapi_auth.openid.session.cookie import CookieBackend
from fastapi_auth.openid.session.jwt import JWTBackend
from fastapi_auth.openid.session.store import MemoryStore
from fastapi_auth.openid.settings import OidcSettings

_JWKS = {"keys": []}


def _settings(**over) -> OidcSettings:
    base = dict(
        entity_id="https://rp.example",
        base_url="https://rp.example",
        fed_jwks=_JWKS,
        session_secret="s" * 32,
    )
    base.update(over)
    return OidcSettings(**base)  # type: ignore


def test_make_store_memory_default():
    assert isinstance(make_store(_settings()), MemoryStore)


def test_make_backend_cookie_default():
    settings = _settings()
    assert isinstance(make_backend(settings, make_store(settings)), CookieBackend)


def test_make_backend_jwt():
    settings = _settings(backend="jwt")
    assert isinstance(make_backend(settings, make_store(settings)), JWTBackend)
