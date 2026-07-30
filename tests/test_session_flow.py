"""End-to-end: federated login establishes a session usable via current_user."""

import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings


def _rp(op: OpFixture) -> OidcRP:
    settings = OidcSettings(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        # TestClient speaks http://testserver; a Secure cookie would be dropped
        # by the client jar and never sent to /me. Disable Secure for the test.
        cookie_secure=False,
    )
    return OidcRP(settings, clock=lambda: NOW + 10)


def test_login_establishes_session_and_current_user_reads_it() -> None:
    """Test that login establishes a session readable via current_user()."""
    op = OpFixture()
    rp = _rp(op)
    app = FastAPI()
    rp.mount(app)

    @app.get("/me")
    async def me(user: FederatedIdentity = Depends(rp.current_user())) -> dict[str, str | None]:  # noqa: B008
        return {"sub": user.sub}

    with respx.mock(assert_all_called=False) as router:
        op.mount(router)
        client = TestClient(app)
        # unauthenticated -> 401
        assert client.get("/me").status_code == 401
        # drive login
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
        cb = client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
        assert cb.status_code == 303
        # the session cookie set on the callback response is now in the client jar
        me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["sub"] == "u1"
