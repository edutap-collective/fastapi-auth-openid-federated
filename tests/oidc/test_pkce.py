"""Tests for PKCE code verifier/challenge (RFC 7636)."""

from fastapi_auth.openid.oidc import pkce


def test_rfc7636_known_vector():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.code_challenge_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_verifier_length_and_charset():
    v = pkce.create_code_verifier()
    assert 43 <= len(v) <= 128
    assert all(c.isalnum() or c in "-._~" for c in v)


def test_challenge_has_no_padding():
    assert "=" not in pkce.code_challenge_s256(pkce.create_code_verifier())
