"""Tests for the OIDC/eduPerson claim registry."""

import pytest

from fastapi_auth.openid.identity import registry


def test_resolve_standard_claim():
    d = registry.resolve("email")
    assert d is not None
    assert d.field == "mail"
    assert d.multivalued is True


def test_resolve_sub_and_iss():
    sub_def = registry.resolve("sub")
    assert sub_def is not None
    assert sub_def.field == "sub"
    iss_def = registry.resolve("iss")
    assert iss_def is not None
    assert iss_def.field == "iss"


def test_resolve_eduperson_claims():
    eppn_def = registry.resolve("eduperson_principal_name")
    assert eppn_def is not None
    assert eppn_def.field == "eppn"
    aff_def = registry.resolve("eduperson_scoped_affiliation")
    assert aff_def is not None
    assert aff_def.field == "scoped_affiliation"
    assert aff_def.multivalued is True


def test_resolve_schac():
    home_org_def = registry.resolve("schac_home_organization")
    assert home_org_def is not None
    assert home_org_def.field == "home_organization"


def test_unknown_returns_none():
    assert registry.resolve("no_such_claim") is None


@pytest.mark.parametrize(
    "field", ["sub", "iss", "eppn", "mail", "scoped_affiliation", "home_organization"]
)
def test_every_expected_field_present(field):
    assert any(d.field == field for d in registry.REGISTRY)
