"""Tests for mapping a claims dict onto FederatedIdentity."""

from fastapi_auth.openid.identity.mapper import map_claims


def test_scalar_claim_maps():
    ident = map_claims({"sub": "u123", "iss": "https://op.example"})
    assert ident.sub == "u123"
    assert ident.iss == "https://op.example"


def test_scalar_email_coerced_to_list():
    ident = map_claims({"email": "a@lmu.de", "email_verified": True})
    assert ident.mail == ["a@lmu.de"]
    assert ident.email_verified is True


def test_list_claim_kept_as_list():
    ident = map_claims({"eduperson_scoped_affiliation": ["staff@lmu.de", "member@lmu.de"]})
    assert ident.scoped_affiliation == ["staff@lmu.de", "member@lmu.de"]


def test_eduperson_principal_name_maps_to_eppn():
    assert map_claims({"eduperson_principal_name": "u@lmu.de"}).eppn == "u@lmu.de"


def test_claims_escape_hatch_holds_all_raw_claims():
    raw = {"sub": "u", "email": "a@lmu.de", "custom_claim": "x"}
    ident = map_claims(raw)
    assert ident.claims == raw
    assert ident.claims["custom_claim"] == "x"


def test_none_value_is_skipped():
    ident = map_claims({"sub": None, "email": None})
    assert ident.sub is None
    assert ident.mail == []


def test_auth_time_epoch_int():
    ident = map_claims({"auth_time": 1700000000})
    assert ident.auth_time == 1700000000
