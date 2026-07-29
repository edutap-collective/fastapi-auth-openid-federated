"""Tests for stable identifier selection."""

from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity


def test_primary_wins_when_present():
    ident = FederatedIdentity(sub="u123", eppn="u@lmu.de")
    assert select_identifier(ident, "sub", ["eppn"]) == "u123"


def test_falls_back_when_primary_missing():
    ident = FederatedIdentity(eppn="u@lmu.de")
    assert select_identifier(ident, "sub", ["eppn"]) == "u@lmu.de"


def test_returns_none_when_nothing_matches():
    assert select_identifier(FederatedIdentity(), "sub", ["eppn"]) is None


def test_list_field_uses_first_value():
    ident = FederatedIdentity(mail=["first@lmu.de", "second@lmu.de"])
    assert select_identifier(ident, "mail") == "first@lmu.de"


def test_public_api_reexports():
    from fastapi_auth import openid

    assert hasattr(openid, "FederatedIdentity")
    assert hasattr(openid, "map_claims")
    assert hasattr(openid, "select_identifier")
