"""FastAPI router factory for the OpenID Connect relying-party endpoints.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from fastapi_auth.openid.discovery.embedded import render_wayf
from fastapi_auth.openid.federation.entity_configuration import sign_rp_entity_configuration
from fastapi_auth.openid.oidc import login
from fastapi_auth.openid.oidc.errors import OidcError
from fastapi_auth.openid.redirect import is_safe_redirect

if TYPE_CHECKING:
    from fastapi_auth.openid.rp import OidcRP

_ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt"


def build_router(rp: OidcRP) -> APIRouter:
    """Build the well-known/login/callback routes bound to this OidcRP."""
    router = APIRouter()
    settings = rp.settings

    @router.get("/.well-known/openid-federation")
    async def entity_configuration() -> Response:
        rp_metadata = dict(settings.rp_metadata)
        rp_metadata.setdefault("redirect_uris", [settings.callback_url])
        if settings.post_logout_redirect_uris:
            rp_metadata.setdefault("post_logout_redirect_uris", settings.post_logout_redirect_uris)
        token = sign_rp_entity_configuration(
            entity_id=settings.entity_id,
            fed_jwks_public=rp.fed_public,
            fed_signing_key=rp.fed_key,
            authority_hints=settings.authority_hints,
            rp_metadata=rp_metadata,
        )
        return Response(token, media_type=_ENTITY_STATEMENT_MEDIA_TYPE)

    @router.get("/login")
    async def login_endpoint(op: str | None = None, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, settings.allowed_redirect_hosts)
        chosen_op = op
        if chosen_op is None:
            if settings.discovery_mode == "embedded":
                html = render_wayf(
                    rp.op_choices(), f"{settings.mount_path}/login", safe_next, rp.jinja_env
                )
                return Response(html, media_type="text/html")
            # passthrough
            if settings.fixed_op_entity_id is None:
                raise HTTPException(status_code=400, detail="no OpenID Provider selected")
            chosen_op = settings.fixed_op_entity_id
        try:
            redirect = await login.begin_login(
                http_client=rp.http_client,
                settings=settings,
                fed_signing_key=rp.fed_key,
                op_entity_id=chosen_op,
                next_url=safe_next,
                state_store=rp.state_store,
                now=rp.clock(),
            )
        except OidcError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return RedirectResponse(redirect.url, status_code=303)

    @router.get("/callback")
    async def callback(
        request: Request,
        state: str,
        code: str = "",
        error: str = "",
        error_description: str = "",
    ) -> Response:
        if error:
            detail = f"OpenID Provider returned an error: {error} {error_description}".strip()
            raise HTTPException(status_code=400, detail=detail)
        login_state = rp.state_store.pop(state, now=rp.clock())
        if login_state is None:
            raise HTTPException(status_code=400, detail="unknown or expired login state")
        if not code:
            raise HTTPException(status_code=400, detail="missing authorization code")
        try:
            identity = await login.complete_login(
                http_client=rp.http_client,
                settings=settings,
                fed_signing_key=rp.fed_key,
                login_state=login_state,
                code=code,
                now=rp.clock(),
            )
        except OidcError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return await rp.on_authenticated(request, identity, login_state.next_url)

    @router.get("/logout")
    async def logout(request: Request, next: str = "/") -> Response:
        safe_next = is_safe_redirect(next, settings.allowed_redirect_hosts)
        identity = await rp.backend.load(request)
        op_url = await rp.op_logout_url(identity)
        target = op_url if op_url is not None else safe_next
        response = RedirectResponse(target, status_code=303)
        await rp.backend.revoke(request, response)
        return response

    return router
