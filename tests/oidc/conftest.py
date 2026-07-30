"""OP + federation test double for OIDC login flow tests.

Builds an in-memory federation (trust anchor -> OP leaf) whose OP entity
publishes ``openid_provider`` metadata (endpoints + protocol jwks) and mocks the
``.well-known``/fetch endpoints plus the OP token/userinfo endpoints via respx.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import fetch, jose

NOW = 1_700_000_000
RP_ENTITY = "https://rp.example"
OP_ENTITY = "https://op.example"
TA_ENTITY = "https://ta.example"


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(key_size=2048, parameters={"kid": kid}, private=True)


@dataclass
class OpFixture:
    """A federated OP with federation keys, protocol keys and signed statements."""

    fed_key: RSAKey = field(default_factory=lambda: _key("op-fed"))
    protocol_key: RSAKey = field(default_factory=lambda: _key("op-proto"))
    ta_key: RSAKey = field(default_factory=lambda: _key("ta-fed"))
    rp_fed_key: RSAKey = field(default_factory=lambda: _key("rp-fed"))
    now: int = NOW
    with_end_session: bool = False

    def op_metadata(self) -> dict[str, object]:
        provider = {
            "issuer": OP_ENTITY,
            "authorization_endpoint": f"{OP_ENTITY}/authorize",
            "token_endpoint": f"{OP_ENTITY}/token",
            "userinfo_endpoint": f"{OP_ENTITY}/userinfo",
            "jwks": jose.public_jwks(KeySet([self.protocol_key])),
        }
        if self.with_end_session:
            provider["end_session_endpoint"] = f"{OP_ENTITY}/logout"
        return {"openid_provider": provider}

    def op_entity_configuration(self) -> str:
        claims = es.build_entity_configuration(
            entity_id=OP_ENTITY,
            jwks=jose.public_jwks(KeySet([self.fed_key])),
            authority_hints=[TA_ENTITY],
            metadata=self.op_metadata(),
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.fed_key)

    def ta_entity_configuration(self) -> str:
        claims = es.build_entity_configuration(
            entity_id=TA_ENTITY,
            jwks=jose.public_jwks(KeySet([self.ta_key])),
            metadata={"federation_entity": {"federation_fetch_endpoint": f"{TA_ENTITY}/fetch"}},
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.ta_key)

    def subordinate_about_op(self) -> str:
        claims = es.build_subordinate_statement(
            issuer=TA_ENTITY,
            subject=OP_ENTITY,
            jwks=jose.public_jwks(KeySet([self.fed_key])),
            now=self.now,
        )
        return jose.sign_entity_statement(claims, self.ta_key)

    def trust_anchors(self) -> dict[str, dict[str, object]]:
        return {TA_ENTITY: jose.public_jwks(KeySet([self.ta_key]))}

    def id_token(self, *, nonce: str, sub: str = "u1", **over: object) -> str:
        claims: dict[str, object] = {
            "iss": OP_ENTITY,
            "sub": sub,
            "aud": RP_ENTITY,
            "nonce": nonce,
            "iat": self.now,
            "exp": self.now + 300,
            "email": "u@lmu.de",
            "eduperson_principal_name": f"{sub}@lmu.de",
        }
        claims.update(over)
        header = {"alg": "RS256", "kid": self.protocol_key.kid}
        return jwt.encode(header, claims, self.protocol_key, algorithms=["RS256"])

    def mount(self, router: respx.Router) -> None:
        headers = {"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        router.get(fetch.well_known_url(OP_ENTITY)).respond(
            200, text=self.op_entity_configuration(), headers=headers
        )
        router.get(fetch.well_known_url(TA_ENTITY)).respond(
            200, text=self.ta_entity_configuration(), headers=headers
        )
        router.get(f"{TA_ENTITY}/fetch").respond(
            200, text=self.subordinate_about_op(), headers=headers
        )


@pytest.fixture
def op() -> OpFixture:
    return OpFixture()


@pytest.fixture
def mock_router() -> respx.Router:
    return respx.mock(assert_all_called=False)
