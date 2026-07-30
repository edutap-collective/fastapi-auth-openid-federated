"""Tests for the signed authorization request object (JAR, federation §12.1.1.1)."""

from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import request_object as ro

NOW = 1_700_000_000


def _key(kid: str = "rp-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_request_object_claims_shape():
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid", "profile"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    assert claims["iss"] == "https://rp.example"
    assert claims["client_id"] == "https://rp.example"
    assert claims["aud"] == "https://op.example"  # OP entity id only
    assert "sub" not in claims  # MUST NOT be present
    assert claims["response_type"] == "code"
    assert claims["scope"] == "openid profile"  # space-joined
    assert claims["code_challenge"] == "cc"
    assert claims["code_challenge_method"] == "S256"
    assert claims["state"] == "st"
    assert claims["nonce"] == "no"
    assert claims["exp"] == NOW + 120
    assert claims["jti"] == "j1"


def test_sign_request_object_typ_header_and_verifies():
    key = _key("rp-1")
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    token = ro.sign_request_object(claims, key)
    assert jose.peek_header(token)["typ"] == ro.REQUEST_OBJECT_TYP
    verified = jose.verify_signature(token, KeySet([key]), algorithms=["RS256"])
    assert verified["aud"] == "https://op.example"


def test_sign_request_object_includes_trust_chain_header():
    key = _key("rp-1")
    claims = ro.build_request_object(
        client_id="https://rp.example",
        op_entity_id="https://op.example",
        redirect_uri="https://rp.example/openid/callback",
        scope=["openid"],
        state="st",
        nonce="no",
        code_challenge="cc",
        now=NOW,
        jti="j1",
    )
    token = ro.sign_request_object(claims, key, trust_chain=["ec.jwt", "sub.jwt"])
    assert jose.peek_header(token)["trust_chain"] == ["ec.jwt", "sub.jwt"]
