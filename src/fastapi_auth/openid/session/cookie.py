"""Signed-cookie session backend (server-side session in a store).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.store import Store
from fastapi_auth.openid.settings import OidcSettings

_SALT = "fastapi-auth-openid-session"


class CookieBackend:
    """Server-side session addressed by a signed session id in a cookie."""

    def __init__(self, settings: OidcSettings, store: Store) -> None:
        """Initialize the cookie-based session backend."""
        if not settings.session_secret:
            raise ValueError("cookie session backend requires a non-empty session_secret")
        self._settings = settings
        self._store = store
        self._serializer = URLSafeTimedSerializer(settings.session_secret, salt=_SALT)

    async def establish(self, identity: FederatedIdentity, response: Response) -> None:
        """Create a server-side session and set a signed session-id cookie."""
        sid = secrets.token_urlsafe(32)
        await self._store.save_session(sid, identity, self._settings.session_ttl)
        response.set_cookie(
            self._settings.session_cookie_name,
            self._serializer.dumps(sid),
            max_age=self._settings.session_ttl,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    async def load(self, request: Request) -> FederatedIdentity | None:
        """Load the session identity from the signed cookie, or None if invalid."""
        sid = self._read_sid(request)
        if sid is None:
            return None
        return await self._store.load_session(sid)

    async def revoke(self, request: Request, response: Response) -> None:
        """Delete the server-side session and clear the cookie."""
        sid = self._read_sid(request)
        if sid is not None:
            await self._store.delete_session(sid)
        response.delete_cookie(
            self._settings.session_cookie_name,
            httponly=True,
            secure=self._settings.cookie_secure,
            samesite="lax",
        )

    def _read_sid(self, request: Request) -> str | None:
        """Read and verify the signed session id from the cookie."""
        raw = request.cookies.get(self._settings.session_cookie_name)
        if not raw:
            return None
        try:
            return self._serializer.loads(raw, max_age=self._settings.session_ttl)
        except (BadSignature, SignatureExpired):
            return None
