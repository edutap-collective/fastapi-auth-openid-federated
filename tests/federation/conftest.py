"""In-memory OpenID Federation for tests: keys, statements and respx routes.

Builds a small federation (trust anchor -> intermediate -> leaf) whose entity
configurations and subordinate statements are signed with per-entity test keys,
and mocks the ``.well-known`` and federation fetch endpoints via respx so the
async fetch layer and trust-chain logic can run end-to-end without a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import httpx
import pytest
import respx
from joserfc.jwk import KeySet, RSAKey

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import fetch, jose

NOW = 1_700_000_000


@dataclass
class Entity:
    """A federation participant with its own signing key."""

    entity_id: str
    key: RSAKey
    authority_hints: list[str] = field(default_factory=list)
    metadata: dict[str, object] | None = None
    fetch_endpoint: str | None = None

    def public_jwks(self) -> dict[str, object]:
        return jose.public_jwks(KeySet([self.key]))

    def entity_configuration(self, *, now: int = NOW) -> str:
        metadata = dict(self.metadata or {})
        if self.fetch_endpoint is not None:
            fed = dict(cast("dict[str, object]", metadata.get("federation_entity", {})))
            fed["federation_fetch_endpoint"] = self.fetch_endpoint
            metadata["federation_entity"] = fed
        claims = es.build_entity_configuration(
            entity_id=self.entity_id,
            jwks=self.public_jwks(),
            authority_hints=self.authority_hints or None,
            metadata=metadata or None,
            now=now,
        )
        return jose.sign_entity_statement(claims, self.key)


@dataclass
class Federation:
    """A registry of entities plus subordinate-statement minting + routing."""

    entities: dict[str, Entity] = field(default_factory=dict)
    now: int = NOW

    def add_entity(
        self,
        entity_id: str,
        *,
        kid: str | None = None,
        authority_hints: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        fetch_endpoint: str | None = None,
    ) -> Entity:
        key = RSAKey.generate_key(key_size=2048, parameters={"kid": kid or entity_id}, private=True)
        entity = Entity(
            entity_id=entity_id,
            key=key,
            authority_hints=authority_hints or [],
            metadata=metadata,
            fetch_endpoint=fetch_endpoint,
        )
        self.entities[entity_id] = entity
        return entity

    def subordinate(
        self,
        issuer_id: str,
        subject_id: str,
        *,
        metadata_policy: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
        now: int | None = None,
    ) -> str:
        """Mint a subordinate statement (issuer about subject; subject's jwks)."""
        issuer = self.entities[issuer_id]
        subject = self.entities[subject_id]
        claims = es.build_subordinate_statement(
            issuer=issuer_id,
            subject=subject_id,
            jwks=subject.public_jwks(),
            metadata_policy=metadata_policy,
            metadata=metadata,
            now=self.now if now is None else now,
        )
        return jose.sign_entity_statement(claims, issuer.key)

    def trust_anchor_keys(self, entity_id: str) -> dict[str, object]:
        return self.entities[entity_id].public_jwks()

    def mount(self, router: respx.Router) -> None:
        """Register respx routes for all well-known endpoints (fetch: see below)."""
        for entity in self.entities.values():
            router.get(fetch.well_known_url(entity.entity_id)).respond(
                200,
                text=entity.entity_configuration(now=self.now),
                headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE},
            )

    def mount_fetch(self, router: respx.Router, superior_id: str) -> None:
        """Register the fetch endpoint of ``superior_id`` to mint on demand."""
        superior = self.entities[superior_id]
        assert superior.fetch_endpoint is not None

        def _handler(request: httpx.Request) -> httpx.Response:
            sub = request.url.params["sub"]
            return httpx.Response(
                200,
                text=self.subordinate(superior_id, sub, now=self.now),
                headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE},
            )

        router.get(superior.fetch_endpoint).mock(side_effect=_handler)


@pytest.fixture
def federation() -> Federation:
    """A fresh, empty in-memory federation."""
    return Federation()


@pytest.fixture
def mock_router() -> respx.Router:
    """A respx router usable as a context manager in async tests."""
    return respx.mock(assert_all_called=False)
