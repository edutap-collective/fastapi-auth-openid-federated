"""OidcRP facade: wires settings, federation keys, session and router.

Composition root for one configured relying party. The user-session layer
(store + backend, selected via ``factory.py``) is established on a
successful callback through a pluggable ``on_authenticated`` seam (default:
establish the session, then redirect to the validated ``next`` target).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.discovery.embedded import OpChoice
from fastapi_auth.openid.factory import make_backend, make_store
from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import FederationError
from fastapi_auth.openid.federation.trust_chain import resolve_and_validate
from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.login_state import LoginStateStore
from fastapi_auth.openid.redirect import is_safe_redirect
from fastapi_auth.openid.router import build_router
from fastapi_auth.openid.settings import OidcSettings

#: Default timeout for the RP-owned httpx.AsyncClient (connect+read+write+pool).
_DEFAULT_HTTP_TIMEOUT = httpx.Timeout(10.0)

_TEMPLATES_DIR = Path(__file__).parent / "discovery" / "templates"

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
        """Build federation keys, login-state, session store/backend and router."""
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
        self.store = make_store(settings)
        self.backend = make_backend(settings, self.store)
        # autoescape MUST stay on: the WAYF page renders untrusted OP display
        # names / entity ids sourced from federation metadata.
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=select_autoescape()
        )
        self.on_authenticated = on_authenticated or self._default_on_authenticated
        self.router = build_router(self)

    async def _default_on_authenticated(
        self, request: Request, identity: FederatedIdentity, next_url: str
    ) -> Response:
        target = is_safe_redirect(next_url, self.settings.allowed_redirect_hosts)
        response = RedirectResponse(target, status_code=303)
        await self.backend.establish(identity, response)
        return response

    def identifier(self, identity: FederatedIdentity) -> str | None:
        """Return this RP's chosen stable identifier (sub, with fallbacks)."""
        return select_identifier(identity, "sub", ["eppn", "preferred_username"])

    def op_choices(self) -> list[OpChoice]:
        """Build the WAYF OP list from settings.op_list (display defaults to entity_id)."""
        choices: list[OpChoice] = []
        for entry in self.settings.op_list:
            entity_id = entry.get("entity_id")
            if not entity_id:
                continue
            choices.append(
                OpChoice(entity_id=entity_id, display_name=entry.get("display_name") or entity_id)
            )
        return choices

    def mount(self, app: FastAPI, **kwargs: Any) -> None:
        """Include this RP's router under ``settings.mount_path``.

        ``**kwargs`` are forwarded verbatim to ``FastAPI.include_router`` (e.g.
        ``dependencies=[...]``); its many keyword-only parameters carry
        heterogeneous ``Annotated`` types that cannot be narrowed here without
        duplicating FastAPI's own signature, hence the escape to ``Any``.
        """
        app.include_router(self.router, prefix=self.settings.mount_path, **kwargs)

    def optional_user(self) -> Callable[[Request], Awaitable[FederatedIdentity | None]]:
        """Dependency returning the FederatedIdentity or None."""

        async def _dep(request: Request) -> FederatedIdentity | None:
            return await self.backend.load(request)

        return _dep

    def current_user(self) -> Callable[[Request], Awaitable[FederatedIdentity]]:
        """Dependency returning the FederatedIdentity or raising 401."""

        async def _dep(request: Request) -> FederatedIdentity:
            identity = await self.backend.load(request)
            if identity is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            return identity

        return _dep

    async def op_logout_url(self, identity: FederatedIdentity | None) -> str | None:
        """Best-effort end_session_endpoint URL for the identity's OP, or None.

        Returns None (→ local logout) unless op-logout is enabled, the identity
        carries an ``iss``, a post_logout_redirect_uri is registered, and the OP
        resolves to an ``end_session_endpoint``. Any federation failure falls
        back to a local logout (this must never block clearing the session).
        """
        if not self.settings.enable_op_logout or identity is None:
            return None
        issuer = identity.iss
        if not issuer or not self.settings.post_logout_redirect_uris:
            return None
        try:
            resolved = await resolve_and_validate(
                self.http_client,
                issuer,
                self.settings.trust_anchors,
                entity_type="openid_provider",
                leeway=self.settings.clock_skew,
                now=self.clock(),
            )
        except FederationError:
            # Best-effort logout: any resolution/validation failure → local logout.
            return None
        endpoint = resolved.metadata.get("end_session_endpoint")
        if not isinstance(endpoint, str):
            return None
        query = urlencode(
            {
                "client_id": self.settings.entity_id,
                "post_logout_redirect_uri": self.settings.post_logout_redirect_uris[0],
            }
        )
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{query}"

    async def aclose(self) -> None:
        """Close the shared httpx client and the session store."""
        await self.http_client.aclose()
        await self.store.aclose()


__all__ = ["OidcRP"]
