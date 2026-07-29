"""Low-level JOSE helpers for OpenID Federation entity statements.

All entity statements are signed JWTs with an explicit ``typ`` of
``entity-statement+jwt`` (OpenID Federation 1.0, Section 3). Signature
verification here is deliberately *signature-only*; time/claim validation is a
separate, explicit step (see ``entity_statement`` / ``trust_chain``), because
``joserfc.jwt.decode`` does not check ``exp``/``iat``.

``peek_*`` reads an unverified token header/payload — used ONLY to decide which
key or endpoint to fetch during trust-chain resolution. Never trust its output
before ``verify_signature`` has confirmed the signature.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Sequence
from typing import cast

from joserfc import jwt
from joserfc.errors import BadSignatureError, InvalidKeyIdError
from joserfc.jwk import Key, KeySet, KeySetSerialization

from fastapi_auth.openid.federation.errors import SignatureError

ENTITY_STATEMENT_TYP = "entity-statement+jwt"

#: Algorithms we are willing to accept/produce. ``none`` is never allowed.
DEFAULT_SIGNING_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "PS256",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)

_EC_CRV_TO_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


def now_epoch() -> int:
    """Return the current time as integer seconds since the epoch."""
    return int(time.time())


def load_keyset(jwks: dict[str, object]) -> KeySet:
    """Import a public/private JWKS dict (``{"keys": [...]}``) into a KeySet."""
    return KeySet.import_key_set(cast(KeySetSerialization, jwks))


def public_jwks(keyset: KeySet) -> dict[str, object]:
    """Export a KeySet to a public-only JWKS dict suitable for publishing."""
    return cast(dict[str, object], keyset.as_dict(private=False))


def signing_alg(key: Key) -> str:
    """Pick the JWS ``alg`` for a signing key from its type/curve."""
    material = key.as_dict(private=False)
    kty = material["kty"]
    if kty == "RSA":
        return "RS256"
    if kty == "EC":
        crv = str(material.get("crv", ""))
        alg = _EC_CRV_TO_ALG.get(crv)
        if alg is None:
            raise SignatureError(f"unsupported EC curve: {crv!r}")
        return alg
    if kty == "OKP":
        return "EdDSA"
    raise SignatureError(f"unsupported key type: {kty!r}")


def sign_entity_statement(claims: dict[str, object], key: Key) -> str:
    """Sign a claims dict as an ``entity-statement+jwt`` compact JWS."""
    alg = signing_alg(key)
    header = {"alg": alg, "typ": ENTITY_STATEMENT_TYP, "kid": key.kid}
    return jwt.encode(header, claims, key, algorithms=[alg])


def verify_signature(
    token: str,
    key: KeySet | Key,
    *,
    algorithms: Sequence[str],
) -> dict[str, object]:
    """Verify the JWS signature only and return the claims.

    Raises ``SignatureError`` on a bad signature or when no key in a KeySet
    matches the token's ``kid``. Does NOT validate ``exp``/``iat``.
    """
    try:
        result = jwt.decode(token, key, algorithms=list(algorithms))
    except (BadSignatureError, InvalidKeyIdError) as exc:
        raise SignatureError(str(exc)) from exc
    return dict(result.claims)


def _b64url_segment(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def peek_header(token: str) -> dict[str, object]:
    """Return the UNVERIFIED protected header (for routing decisions only)."""
    header_segment = token.split(".", 2)[0]
    return json.loads(_b64url_segment(header_segment))


def peek_claims(token: str) -> dict[str, object]:
    """Return the UNVERIFIED payload claims (for routing decisions only)."""
    payload_segment = token.split(".", 2)[1]
    return json.loads(_b64url_segment(payload_segment))
