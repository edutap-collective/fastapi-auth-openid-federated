"""Tests for building and verifying entity statements."""

import pytest
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import EntityStatementError, SignatureError

NOW = 1_700_000_000


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def _pub(key: RSAKey) -> dict:
    return jose.public_jwks(KeySet([key]))


def test_entity_configuration_is_self_issued_with_hints():
    key = _key("leaf")
    claims = es.build_entity_configuration(
        entity_id="https://leaf.example",
        jwks=_pub(key),
        authority_hints=["https://ta.example"],
        metadata={"openid_relying_party": {"client_name": "x"}},
        now=NOW,
    )
    assert claims["iss"] == claims["sub"] == "https://leaf.example"
    assert claims["authority_hints"] == ["https://ta.example"]
    assert claims["iat"] == NOW
    assert claims["exp"] == NOW + 3600
    assert es.is_entity_configuration(claims) is True


def test_subordinate_statement_is_not_self_issued_and_has_no_hints():
    key = _key("sub-key")
    claims = es.build_subordinate_statement(
        issuer="https://ta.example",
        subject="https://leaf.example",
        jwks=_pub(key),
        metadata_policy={"openid_provider": {"subject_types_supported": {"value": ["pairwise"]}}},
        now=NOW,
    )
    assert claims["iss"] == "https://ta.example"
    assert claims["sub"] == "https://leaf.example"
    assert "authority_hints" not in claims
    assert "metadata_policy" in claims
    assert es.is_entity_configuration(claims) is False


def test_verify_statement_roundtrip():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    claims = es.verify_statement(token, KeySet([key]), leeway=0, now=NOW + 10)
    assert claims["sub"] == "https://leaf.example"


def test_verify_statement_rejects_expired():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(
            entity_id="https://leaf.example", jwks=_pub(key), lifetime=100, now=NOW
        ),
        key,
    )
    with pytest.raises(EntityStatementError, match="expired"):
        es.verify_statement(token, KeySet([key]), leeway=0, now=NOW + 1000)


def test_verify_statement_rejects_future_iat():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    with pytest.raises(EntityStatementError, match="future"):
        es.verify_statement(token, KeySet([key]), leeway=0, now=NOW - 1000)


def test_verify_statement_rejects_bad_signature():
    key = _key("leaf")
    token = jose.sign_entity_statement(
        es.build_entity_configuration(entity_id="https://leaf.example", jwks=_pub(key), now=NOW),
        key,
    )
    with pytest.raises(SignatureError):
        es.verify_statement(token, KeySet([_key("attacker")]), now=NOW + 10)


def test_verify_statement_rejects_wrong_typ():
    from joserfc import jwt

    key = _key("leaf")
    claims = es.build_entity_configuration(
        entity_id="https://leaf.example", jwks=_pub(key), now=NOW
    )
    token = jwt.encode(
        {"alg": "RS256", "typ": "JWT", "kid": "leaf"},
        claims,
        key,
        algorithms=["RS256"],
    )
    with pytest.raises(EntityStatementError, match="typ"):
        es.verify_statement(token, KeySet([key]), now=NOW + 10)


def test_verify_statement_rejects_missing_required_claim():
    key = _key("leaf")
    # Missing "jwks" -> structural failure.
    token = jose.sign_entity_statement(
        {"iss": "https://leaf.example", "sub": "https://leaf.example", "iat": NOW, "exp": NOW + 10},
        key,
    )
    with pytest.raises(EntityStatementError, match="jwks"):
        es.verify_statement(token, KeySet([key]), now=NOW + 1)
