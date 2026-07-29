"""Tests for publishing the RP's own entity configuration."""

from typing import Any, cast

from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_configuration as ec
from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import jose

NOW = 1_700_000_000


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_build_rp_entity_configuration_shape():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    claims = ec.build_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        authority_hints=["https://ta.example"],
        rp_metadata={
            "client_name": "My RP",
            "redirect_uris": ["https://rp.example/openid/callback"],
        },
        now=NOW,
    )
    assert claims["iss"] == claims["sub"] == "https://rp.example"
    assert claims["authority_hints"] == ["https://ta.example"]
    assert claims["jwks"] == pub
    metadata = cast(dict[str, Any], claims["metadata"])
    assert metadata["openid_relying_party"]["client_name"] == "My RP"


def test_signed_rp_entity_configuration_verifies_against_own_jwks():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    token = ec.sign_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        fed_signing_key=key,
        authority_hints=["https://ta.example"],
        rp_metadata={"client_name": "My RP"},
        now=NOW,
    )
    # Self-signed: verifiable with the jwks it publishes.
    claims = es.verify_statement(token, jose.load_keyset(pub), now=NOW + 10)
    assert es.is_entity_configuration(claims) is True
    metadata = cast(dict[str, Any], claims["metadata"])
    assert metadata["openid_relying_party"]["client_name"] == "My RP"


def test_federation_metadata_is_included_when_given():
    key = _key("rp-fed")
    pub = jose.public_jwks(KeySet([key]))
    claims = ec.build_rp_entity_configuration(
        entity_id="https://rp.example",
        fed_jwks_public=pub,
        authority_hints=["https://ta.example"],
        rp_metadata={"client_name": "My RP"},
        federation_metadata={"organization_name": "Example Org"},
        now=NOW,
    )
    metadata = cast(dict[str, Any], claims["metadata"])
    assert metadata["federation_entity"]["organization_name"] == "Example Org"
