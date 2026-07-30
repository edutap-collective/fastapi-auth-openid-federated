"""Router/facade tests via FastAPI TestClient over the OP+federation double."""

from typing import Any, cast
from urllib.parse import parse_qs, urlparse

import respx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings


def _rp(op: OpFixture, on_auth=None) -> OidcRP:
    settings = OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=_priv(op),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
    )
    # Inject a fixed clock consistent with OpFixture(now=NOW) so exp/iat checks pass.
    return OidcRP(settings, on_authenticated=on_auth, clock=lambda: NOW + 10)


def _priv(op: OpFixture) -> dict[str, object]:
    return cast(dict[str, object], KeySet([op.rp_fed_key]).as_dict(private=True))


def test_well_known_serves_signed_entity_configuration():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/.well-known/openid-federation")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/entity-statement+jwt")
    claims = jose.verify_signature(
        resp.text, jose.load_keyset(op_rp_public(op)), algorithms=["RS256"]
    )
    assert claims["iss"] == claims["sub"] == RP_ENTITY
    metadata = cast(dict[str, Any], claims["metadata"])
    assert metadata["openid_relying_party"]["redirect_uris"] == [f"{RP_ENTITY}/openid/callback"]


def op_rp_public(op: OpFixture) -> dict:
    return jose.public_jwks(KeySet([op.rp_fed_key]))


def test_login_redirects_to_op_authorization():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        resp = client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
    assert resp.status_code == 303
    parsed = urlparse(resp.headers["location"])
    assert parsed.path == "/authorize"
    assert parse_qs(parsed.query)["client_id"] == [RP_ENTITY]


def test_callback_invokes_on_authenticated():
    op = OpFixture()
    captured = {}

    async def on_auth(request: Request, identity: FederatedIdentity, next_url: str):
        captured["sub"] = identity.sub
        captured["next"] = next_url
        return JSONResponse({"ok": True})

    rp = _rp(op, on_auth=on_auth)
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
        # Capture the login state's value + nonce BEFORE the callback pops it, and
        # bind the OP's id_token to that exact nonce.
        state_value = next(iter(rp.state_store._entries))  # noqa: SLF001 - test introspection
        nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
        router.post(f"{OP_ENTITY}/token").respond(
            200,
            json={
                "access_token": "at",
                "id_token": op.id_token(nonce=nonce),
                "token_type": "Bearer",
            },
        )
        cb = client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
    assert cb.status_code == 200
    assert captured["sub"] == "u1"
    assert captured["next"] == "/app"
