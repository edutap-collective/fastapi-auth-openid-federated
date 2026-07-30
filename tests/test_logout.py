"""Tests for RP-initiated logout (local + best-effort end_session)."""

from typing import Any, cast
from urllib.parse import parse_qs, urlparse

import respx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings


def _rp(op: OpFixture, **over: Any) -> OidcRP:
    base: dict[str, Any] = dict(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        cookie_secure=False,
    )
    base.update(over)
    return OidcRP(OidcSettings(**base), clock=lambda: NOW + 10)


def _login(client: TestClient, op: OpFixture, rp: OidcRP, router: respx.Router) -> None:
    client.get(f"/openid/login?op={OP_ENTITY}&next=/app", follow_redirects=False)
    state_value = next(iter(rp.state_store._entries))  # noqa: SLF001
    nonce = rp.state_store._entries[state_value].nonce  # noqa: SLF001
    router.post(f"{OP_ENTITY}/token").respond(
        200,
        json={
            "access_token": "at",
            "id_token": op.id_token(nonce=nonce),
            "token_type": "Bearer",
        },
    )
    client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)


def test_local_logout_revokes_and_redirects():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)

    @app.get("/me")
    async def me(request: Request):
        ident = await rp.backend.load(request)
        return JSONResponse({"authenticated": ident is not None})

    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        _login(client, op, rp, router)
        assert client.get("/me").json()["authenticated"] is True
        resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/bye"
        # session gone
        assert client.get("/me").json()["authenticated"] is False


def test_op_logout_redirects_to_end_session_when_enabled():
    op = OpFixture(with_end_session=True)
    rp = _rp(
        op,
        enable_op_logout=True,
        post_logout_redirect_uris=[f"{RP_ENTITY}/openid/post-logout"],
    )
    app = FastAPI()
    rp.mount(app)
    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        _login(client, op, rp, router)
        resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith(f"{OP_ENTITY}/logout")
    q = parse_qs(urlparse(location).query)
    assert q["client_id"] == [RP_ENTITY]
    assert q["post_logout_redirect_uri"] == [f"{RP_ENTITY}/openid/post-logout"]


def test_logout_without_session_redirects_local():
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/logout?next=/bye", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/bye"


def test_well_known_publishes_post_logout_redirect_uris():
    op = OpFixture()
    rp = _rp(op, post_logout_redirect_uris=[f"{RP_ENTITY}/openid/post-logout"])
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)

    resp = client.get("/openid/.well-known/openid-federation")
    rp_public_jwks = jose.load_keyset(jose.public_jwks(KeySet([op.rp_fed_key])))
    claims = jose.verify_signature(resp.text, rp_public_jwks, algorithms=["RS256"])
    metadata = cast(dict[str, Any], claims["metadata"])
    rp_meta = metadata["openid_relying_party"]
    assert rp_meta["post_logout_redirect_uris"] == [f"{RP_ENTITY}/openid/post-logout"]


def test_logout_uses_post_logout_default_when_no_next():
    op = OpFixture()
    rp = _rp(op, post_logout_default="/goodbye")
    app = FastAPI()
    rp.mount(app)
    client = TestClient(app)
    resp = client.get("/openid/logout", follow_redirects=False)  # no ?next
    assert resp.status_code == 303
    assert resp.headers["location"] == "/goodbye"
