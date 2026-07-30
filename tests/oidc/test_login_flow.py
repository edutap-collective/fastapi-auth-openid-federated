"""End-to-end tests for begin_login / complete_login over the OP+federation double."""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY

from fastapi_auth.openid import login_state as ls
from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.oidc import login, request_object
from fastapi_auth.openid.settings import OidcSettings


def _settings(op) -> OidcSettings:
    return OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=jose.public_jwks(_ks(op.rp_fed_key)),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        scopes=["openid", "profile", "email"],
    )


def _ks(key):
    from joserfc.jwk import KeySet

    return KeySet([key])


@pytest.mark.asyncio
async def test_begin_login_builds_authorization_redirect(op, mock_router):
    op.mount(mock_router)
    store = ls.LoginStateStore(ttl=300)
    with mock_router:
        async with httpx.AsyncClient() as client:
            redirect = await login.begin_login(
                http_client=client,
                settings=_settings(op),
                fed_signing_key=op.rp_fed_key,
                op_entity_id=OP_ENTITY,
                next_url="/app",
                state_store=store,
                now=NOW + 10,
            )
    parsed = urlparse(redirect.url)
    assert parsed.path == "/authorize"
    q = parse_qs(parsed.query)
    assert q["client_id"] == [RP_ENTITY]
    assert q["response_type"] == ["code"]
    assert "request" in q  # signed request object present
    ro_header = jose.peek_header(q["request"][0])
    assert ro_header["typ"] == request_object.REQUEST_OBJECT_TYP
    # login state stored under the returned state value
    popped = store.pop(redirect.state, now=NOW + 20)
    assert popped is not None
    assert popped.op_entity_id == OP_ENTITY


@pytest.mark.asyncio
async def test_complete_login_returns_identity(op, mock_router):
    op.mount(mock_router)
    store = ls.LoginStateStore(ttl=300)
    settings = _settings(op)
    with mock_router:
        async with httpx.AsyncClient() as client:
            redirect = await login.begin_login(
                http_client=client,
                settings=settings,
                fed_signing_key=op.rp_fed_key,
                op_entity_id=OP_ENTITY,
                next_url="/app",
                state_store=store,
                now=NOW + 10,
            )
            state = store.pop(redirect.state, now=NOW + 20)  # emulate router pop
            assert state is not None
            # OP token endpoint returns an id_token bound to the login nonce.
            mock_router.post(f"{OP_ENTITY}/token").respond(
                200,
                json={
                    "access_token": "at",
                    "id_token": op.id_token(nonce=state.nonce),
                    "token_type": "Bearer",
                },
            )
            identity = await login.complete_login(
                http_client=client,
                settings=settings,
                fed_signing_key=op.rp_fed_key,
                login_state=state,
                code="the-code",
                now=NOW + 30,
            )
    assert identity.sub == "u1"
    assert identity.mail == ["u@lmu.de"]
    assert identity.eppn == "u1@lmu.de"
