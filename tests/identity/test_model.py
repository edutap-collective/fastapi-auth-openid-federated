"""Tests for the FederatedIdentity model."""

from fastapi_auth.openid.identity.model import FederatedIdentity


def test_empty_identity_has_sane_defaults():
    ident = FederatedIdentity()
    assert ident.sub is None
    assert ident.mail == []
    assert ident.scoped_affiliation == []
    assert ident.claims == {}


def test_identity_holds_values():
    ident = FederatedIdentity(
        sub="u123",
        iss="https://op.example",
        eppn="u123@lmu.de",
        scoped_affiliation=["staff@lmu.de", "member@lmu.de"],
        mail=["a@lmu.de"],
        email_verified=True,
        claims={"email": "a@lmu.de"},
    )
    assert ident.sub == "u123"
    assert ident.eppn == "u123@lmu.de"
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]
    assert ident.email_verified is True
    assert ident.claims["email"] == "a@lmu.de"


def test_multivalue_lists_are_independent_between_instances():
    a = FederatedIdentity()
    a.mail.append("x@lmu.de")
    b = FederatedIdentity()
    assert b.mail == []
