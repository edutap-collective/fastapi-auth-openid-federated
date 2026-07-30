"""Tests for OidcSettings configuration."""

from typing import Any, cast

import pytest
from pydantic import ValidationError

from fastapi_auth.openid.settings import OidcSettings

_JWKS: dict[str, Any] = {"keys": [{"kty": "RSA", "kid": "rp-1", "n": "x", "e": "AQAB"}]}
_BASE: dict[str, Any] = dict(
    entity_id="https://rp.example",
    base_url="https://rp.example",
    fed_jwks=_JWKS,
    authority_hints=["https://ta.example"],
    trust_anchors={"https://ta.example": {"keys": []}},
)


def test_defaults_and_derived_urls():
    s = OidcSettings(**_BASE)
    assert s.mount_path == "/openid"
    assert s.redirect_path == "/openid/callback"
    assert s.callback_url == "https://rp.example/openid/callback"
    assert s.absolute_url("/login") == "https://rp.example/openid/login"
    assert s.well_known_path == "/.well-known/openid-federation"
    assert s.scopes == ["openid", "profile", "email"]
    assert s.id_token_signing_alg_values == ["RS256", "ES256"]
    assert s.fetch_userinfo is False


def test_base_url_trailing_slash_stripped_in_callback():
    s = OidcSettings(**cast(dict[str, Any], {**_BASE, "base_url": "https://rp.example/"}))
    assert s.callback_url == "https://rp.example/openid/callback"


def test_missing_required_field_raises():
    incomplete = {k: v for k, v in _BASE.items() if k != "entity_id"}
    with pytest.raises(ValidationError):
        OidcSettings(**incomplete)


def test_redirect_path_must_be_under_mount_path():
    with pytest.raises(ValidationError, match="mount_path"):
        OidcSettings(**cast(dict[str, Any], {**_BASE, "redirect_path": "/elsewhere/callback"}))


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("OIDC_ENTITY_ID", "https://rp.example")
    monkeypatch.setenv("OIDC_BASE_URL", "https://rp.example")
    monkeypatch.setenv("OIDC_FED_JWKS", '{"keys": []}')
    s = OidcSettings()
    assert s.entity_id == "https://rp.example"
    assert s.fed_jwks == {"keys": []}


def test_lists_from_values():
    extra = {"scopes": ["openid"], "allowed_redirect_hosts": ["rp.example"]}
    s = OidcSettings(**cast(dict[str, Any], {**_BASE, **extra}))
    assert s.scopes == ["openid"]
    assert s.allowed_redirect_hosts == ["rp.example"]
