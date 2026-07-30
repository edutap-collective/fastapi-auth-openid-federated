"""Signed authorization request object (JAR) for automatic registration.

OpenID Federation 1.0 §12.1.1.1 requires the authorization request to prove
control of the RP's federation keys via a signed request object typed
``oauth-authz-req+jwt``. Its ``aud`` is the OP's Entity Identifier only, its
``iss``/``client_id`` are the RP's Entity Identifier, and it MUST NOT carry a
``sub`` claim (which would let it be replayed as a private_key_jwt assertion).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Sequence
from typing import cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc import jwt
from joserfc.jwk import Key

from fastapi_auth.openid.federation import jose

REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"


def build_request_object(
    *,
    client_id: str,
    op_entity_id: str,
    redirect_uri: str,
    scope: Sequence[str],
    state: str,
    nonce: str,
    code_challenge: str,
    response_type: str = "code",
    lifetime: int = 120,
    now: int | None = None,
    jti: str | None = None,
) -> dict[str, object]:
    """Build the request-object claims (no ``sub``; ``aud`` = OP entity id)."""
    issued = jose.now_epoch() if now is None else now
    return {
        "iss": client_id,
        "aud": op_entity_id,
        "client_id": client_id,
        "jti": jti if jti is not None else secrets.token_urlsafe(16),
        "iat": issued,
        "exp": issued + lifetime,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scope),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }


def sign_request_object(
    claims: dict[str, object],
    key: Key,
    *,
    trust_chain: list[str] | None = None,
) -> str:
    """Sign a request object as an ``oauth-authz-req+jwt`` compact JWS."""
    alg = jose.signing_alg(key)
    header: dict[str, object] = {"alg": alg, "typ": REQUEST_OBJECT_TYP, "kid": key.kid}

    if trust_chain is None:
        return jwt.encode(header, claims, key, algorithms=[alg])

    # When trust_chain is present, manually construct the JWS because joserfc
    # does not allow custom header parameters in compact serialization.
    header["trust_chain"] = trust_chain
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()

    payload_json = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()

    message = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign using the underlying cryptography key
    op_key = key.get_op_key("sign")
    if alg.startswith("RS"):
        # RSA with PKCS1v15 padding
        rsa_key = cast(rsa.RSAPrivateKey, op_key)
        signature_bytes = rsa_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    elif alg.startswith("PS"):
        # RSA with PSS padding
        rsa_key = cast(rsa.RSAPrivateKey, op_key)
        signature_bytes = rsa_key.sign(
            message,
            padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    elif alg.startswith("ES"):
        # ECDSA
        ec_key = cast(ec.EllipticCurvePrivateKey, op_key)
        signature_bytes = ec_key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif alg == "EdDSA":
        # EdDSA
        ed_key = cast(Ed25519PrivateKey, op_key)
        signature_bytes = ed_key.sign(message)
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

    signature_b64 = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{signature_b64}"
