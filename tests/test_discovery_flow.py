"""End-to-end: embedded WAYF selection drives login into a session; logout clears it."""

from typing import Any

import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import KeySet
from tests.oidc.conftest import NOW, OP_ENTITY, RP_ENTITY, OpFixture

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.rp import OidcRP
from fastapi_auth.openid.settings import OidcSettings


def _rp(op: OpFixture) -> OidcRP:
    base: dict[str, Any] = dict(
        entity_id=RP_ENTITY,
        base_url=RP_ENTITY,
        fed_jwks=KeySet([op.rp_fed_key]).as_dict(private=True),
        authority_hints=["https://ta.example"],
        trust_anchors=op.trust_anchors(),
        allowed_redirect_hosts=[],
        session_secret="s" * 32,
        cookie_secure=False,
        discovery_mode="embedded",
        op_list=[{"entity_id": OP_ENTITY, "display_name": "Example OP"}],
    )
    return OidcRP(OidcSettings(**base), clock=lambda: NOW + 10)


def test_wayf_selection_logs_in_then_logout() -> None:
    """Test WAYF selection -> login -> session -> logout flow."""
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
        # 1. WAYF page lists the OP; extract the login link's op param
        wayf = client.get("/openid/login?next=/app", follow_redirects=False)
        assert wayf.status_code == 200
        assert "Example OP" in wayf.text
        # 2. follow the selection (explicit op) -> redirect to OP
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
        # 3. callback establishes session
        client.get(f"/openid/callback?code=c&state={state_value}", follow_redirects=False)
        assert client.get("/me").status_code == 200
        # 4. logout clears it
        client.get("/openid/logout?next=/bye", follow_redirects=False)
        assert client.get("/me").status_code == 401
