"""Tests for the low-level JOSE primitives used by the federation layer."""

from typing import cast

import pytest
from joserfc.jwk import ECKey, KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import SignatureError


def _rsa(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def test_signing_alg_rsa_and_ec():
    assert jose.signing_alg(_rsa("a")) == "RS256"
    assert jose.signing_alg(ECKey.generate_key(crv="P-256", parameters={"kid": "e"})) == "ES256"


def test_public_jwks_strips_private_material():
    ks = KeySet([_rsa("k1")])
    pub = cast(dict, jose.public_jwks(ks))
    assert pub["keys"][0]["kid"] == "k1"
    assert "d" not in pub["keys"][0]  # no private exponent


def test_sign_uses_entity_statement_typ_and_kid():
    key = _rsa("signer-1")
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, key)
    peeked_header = jose.peek_header(token)
    assert peeked_header["typ"] == jose.ENTITY_STATEMENT_TYP
    assert peeked_header["kid"] == "signer-1"
    assert peeked_header["alg"] == "RS256"


def test_sign_and_verify_roundtrip_via_keyset():
    key = _rsa("signer-2")
    token = jose.sign_entity_statement({"iss": "x", "sub": "x", "n": 1}, key)
    keyset = KeySet([_rsa("other"), key])  # signer not first -> kid selection must work
    claims = jose.verify_signature(token, keyset, algorithms=["RS256"])
    assert claims["n"] == 1


def test_verify_wrong_key_raises_signature_error():
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, _rsa("signer-3"))
    with pytest.raises(SignatureError):
        jose.verify_signature(token, KeySet([_rsa("attacker")]), algorithms=["RS256"])


def test_verify_unknown_kid_raises_signature_error():
    token = jose.sign_entity_statement({"iss": "x", "sub": "x"}, _rsa("known"))
    with pytest.raises(SignatureError):
        jose.verify_signature(token, KeySet([_rsa("nope")]), algorithms=["RS256"])


def test_peek_claims_is_unverified_read():
    token = jose.sign_entity_statement({"iss": "leaf", "authority_hints": ["ta"]}, _rsa("k"))
    peeked = jose.peek_claims(token)
    assert peeked["iss"] == "leaf"
    assert peeked["authority_hints"] == ["ta"]
