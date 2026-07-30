"""Adversarial tests for ID-token validation."""

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import id_token as idt
from fastapi_auth.openid.oidc.errors import IdTokenError

NOW = 1_700_000_000
ISS = "https://op.example"
CID = "https://rp.example"


def _op_key(kid: str = "op-1") -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


def _sign(key: RSAKey, claims: dict) -> str:
    return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key, algorithms=["RS256"])


def _claims(**over) -> dict:
    base = {
        "iss": ISS,
        "sub": "u1",
        "aud": CID,
        "nonce": "n1",
        "iat": NOW,
        "exp": NOW + 300,
    }
    base.update(over)
    return base


def _jwks(key: RSAKey) -> dict:
    return jose.public_jwks(KeySet([key]))


def test_valid_id_token_passes():
    key = _op_key()
    token = _sign(key, _claims())
    claims = idt.validate_id_token(
        token,
        op_jwks=_jwks(key),
        issuer=ISS,
        client_id=CID,
        nonce="n1",
        algorithms=["RS256"],
        now=NOW + 10,
    )
    assert claims["sub"] == "u1"


def test_wrong_nonce_rejected():
    key = _op_key()
    token = _sign(key, _claims(nonce="attacker"))
    with pytest.raises(IdTokenError, match="nonce"):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(key),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 10,
        )


def test_wrong_issuer_rejected():
    key = _op_key()
    token = _sign(key, _claims(iss="https://evil.example"))
    with pytest.raises(IdTokenError, match="iss"):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(key),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 10,
        )


def test_aud_without_client_id_rejected():
    key = _op_key()
    token = _sign(key, _claims(aud="https://other.example"))
    with pytest.raises(IdTokenError, match="aud"):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(key),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 10,
        )


def test_multi_aud_requires_matching_azp():
    key = _op_key()
    token = _sign(key, _claims(aud=[CID, "https://other.example"]))  # no azp
    with pytest.raises(IdTokenError, match="azp"):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(key),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 10,
        )


def test_multi_aud_with_correct_azp_passes():
    key = _op_key()
    token = _sign(key, _claims(aud=[CID, "https://other.example"], azp=CID))
    claims = idt.validate_id_token(
        token,
        op_jwks=_jwks(key),
        issuer=ISS,
        client_id=CID,
        nonce="n1",
        algorithms=["RS256"],
        now=NOW + 10,
    )
    assert claims["azp"] == CID


def test_bad_signature_rejected():
    token = _sign(_op_key("real"), _claims())
    with pytest.raises(IdTokenError):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(_op_key("attacker")),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 10,
        )


def test_expired_rejected():
    key = _op_key()
    token = _sign(key, _claims(exp=NOW - 10))
    with pytest.raises(IdTokenError, match="expired"):
        idt.validate_id_token(
            token,
            op_jwks=_jwks(key),
            issuer=ISS,
            client_id=CID,
            nonce="n1",
            algorithms=["RS256"],
            now=NOW + 100,
        )
