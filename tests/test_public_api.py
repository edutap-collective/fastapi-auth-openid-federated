"""Public API surface of fastapi_auth.openid."""

from fastapi_auth import openid


def test_public_reexports_present():
    for name in ("FederatedIdentity", "map_claims", "select_identifier", "OidcRP", "OidcSettings"):
        assert hasattr(openid, name), name


def test_version_present():
    assert openid.__version__


def test_federation_entry_points_importable():
    from fastapi_auth.openid.federation import resolve_and_validate, sign_rp_entity_configuration

    assert callable(resolve_and_validate)
    assert callable(sign_rp_entity_configuration)
