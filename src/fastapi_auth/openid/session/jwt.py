"""Stateless JWT session backend (joserfc).

Signs the identity into a JWT (cookie or ``Authorization: Bearer``). The token
is signed, not encrypted: it carries the identity in plaintext, readable by
whoever holds it. Verification is pinned to the single configured ``jwt_alg``
(closing alg-confusion), and ``exp`` is checked explicitly. Symmetric (HS*)
signs/verifies with a shared secret; an asymmetric ``jwt_alg`` signs with the
first private key in ``jwt_jwks`` and verifies with its public half.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import Request, Response
from joserfc import jwt as jose_jwt
from joserfc.errors import BadSignatureError, DecodeError, InvalidKeyIdError
from joserfc.jwk import Key, KeySet, OctKey

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.settings import OidcSettings


def _first_private_key(keyset: KeySet) -> Key:
    for key in keyset.keys:
        material = key.as_dict(private=True)
        if any(param in material for param in ("d", "k")):
            return key
    raise ValueError("jwt_jwks contains no private signing key")


def _resolve_keys(settings: OidcSettings) -> tuple[Key, Key | KeySet]:
    if settings.jwt_is_symmetric():
        key = OctKey.import_key(settings.jwt_signing_secret)
        return key, key
    if settings.jwt_jwks is None:  # pragma: no cover - validator guarantees this
        raise ValueError("asymmetric jwt_alg requires jwt_jwks")
    signing = _first_private_key(jose.load_keyset(settings.jwt_jwks))
    return signing, KeySet([signing])


class JWTBackend:
    """Carries the identity in a signed JWT (cookie or Authorization: Bearer)."""

    def __init__(self, settings: OidcSettings, *, clock: Callable[[], int] | None = None) -> None:
        """Initialize the JWT backend, resolving key material once from settings.

        ``clock`` (seconds since epoch) is injectable for deterministic tests;
        it defaults to wall-clock time. It is a keyword-only constructor arg, so
        ``establish``/``load`` keep the exact ``SessionBackend`` signatures.
        """
        self._settings = settings
        self._alg = settings.jwt_alg
        self._signing_key, self._verifying_key = _resolve_keys(settings)
        self._clock: Callable[[], int] = clock if clock is not None else (lambda: int(time.time()))

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Sign the identity into a JWT and set it as the session cookie."""
        issued = self._clock()
        subject = select_identifier(identity, "sub", ["eppn", "preferred_username"])
        dump = identity.model_dump(mode="json")
        if self._settings.jwt_attributes is not None:
            attrs = {k: dump[k] for k in self._settings.jwt_attributes if k in dump}
        else:
            attrs = dump
        payload = {
            "sub": subject or "",
            "iat": issued,
            "exp": issued + self._settings.jwt_ttl,
            "attrs": attrs,
        }
        token = jose_jwt.encode(
            {"alg": self._alg, "typ": "JWT"}, payload, self._signing_key, algorithms=[self._alg]
        )
        response.set_cookie(
            self._settings.session_cookie_name,
            token,
            max_age=self._settings.jwt_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Read and verify the JWT from the cookie or Bearer header, or None if invalid."""
        token = self._token_from(request)
        if token is None:
            return None
        try:
            decoded = jose_jwt.decode(token, self._verifying_key, algorithms=[self._alg])
        except (BadSignatureError, DecodeError, InvalidKeyIdError, ValueError):
            return None
        claims = decoded.claims
        moment = self._clock()
        exp = claims.get("exp")
        if not isinstance(exp, int) or exp < moment:
            return None
        attrs = claims.get("attrs", {})
        if not isinstance(attrs, dict):
            return None
        return FederatedIdentity.model_validate(attrs)

    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the session cookie (stateless: no server-side invalidation)."""
        response.delete_cookie(self._settings.session_cookie_name)

    def _token_from(self, request: Request) -> str | None:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return request.cookies.get(self._settings.session_cookie_name)
