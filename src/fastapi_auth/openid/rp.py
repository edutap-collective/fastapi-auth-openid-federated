"""OidcRP facade: wires settings, federation keys, login state and router.

Composition root for one configured relying party. The user-session layer is
Plan 4; until then the callback delegates to a pluggable ``on_authenticated``
seam (default: redirect to the validated ``next`` target).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.login_state import LoginStateStore
from fastapi_auth.openid.redirect import is_safe_redirect
from fastapi_auth.openid.router import build_router
from fastapi_auth.openid.settings import OidcSettings

#: Default timeout for the RP-owned httpx.AsyncClient (connect+read+write+pool).
_DEFAULT_HTTP_TIMEOUT = httpx.Timeout(10.0)

OnAuthenticated = Callable[[Request, FederatedIdentity, str], Awaitable[Response]]


def _first_private_key(jwks: dict[str, object]) -> Key:
    keyset = jose.load_keyset(jwks)
    for key in keyset.keys:
        material = key.as_dict(private=True)
        if any(param in material for param in ("d", "k")):
            return key
    raise ValueError("fed_jwks contains no private signing key")


class OidcRP:
    """Composition root: one configured OpenID Connect relying party."""

    def __init__(
        self,
        settings: OidcSettings,
        *,
        on_authenticated: OnAuthenticated | None = None,
        http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """Build federation keys, the login-state store and the router from settings."""
        self.settings = settings
        # Package-internal but attribute-public (no leading underscore) so the
        # router factory can read them without triggering ruff SLF001.
        self.fed_key = _first_private_key(settings.fed_jwks)
        self.fed_public = jose.public_jwks(KeySet([self.fed_key]))
        self.state_store = LoginStateStore(ttl=settings.login_state_ttl)
        # An externally injected client is owned by the caller (no timeout override
        # here); a client we construct ourselves gets an explicit timeout per the
        # project's HTTPX convention (never rely on the library default).
        self.http_client = (
            http_client
            if http_client is not None
            else httpx.AsyncClient(timeout=_DEFAULT_HTTP_TIMEOUT)
        )
        self.clock = clock if clock is not None else jose.now_epoch
        self.on_authenticated = on_authenticated or self._default_on_authenticated
        self.router = build_router(self)

    async def _default_on_authenticated(
        self, request: Request, identity: FederatedIdentity, next_url: str
    ) -> Response:
        target = is_safe_redirect(next_url, self.settings.allowed_redirect_hosts)
        return RedirectResponse(target, status_code=303)

    def identifier(self, identity: FederatedIdentity) -> str | None:
        """Return this RP's chosen stable identifier (sub, with fallbacks)."""
        return select_identifier(identity, "sub", ["eppn", "preferred_username"])

    def mount(self, app: FastAPI, **kwargs: Any) -> None:
        """Include this RP's router under ``settings.mount_path``.

        ``**kwargs`` are forwarded verbatim to ``FastAPI.include_router`` (e.g.
        ``dependencies=[...]``); its many keyword-only parameters carry
        heterogeneous ``Annotated`` types that cannot be narrowed here without
        duplicating FastAPI's own signature, hence the escape to ``Any``.
        """
        app.include_router(self.router, prefix=self.settings.mount_path, **kwargs)

    async def aclose(self) -> None:
        """Close the shared httpx client (call from a FastAPI lifespan shutdown)."""
        await self.http_client.aclose()


__all__ = ["OidcRP"]
