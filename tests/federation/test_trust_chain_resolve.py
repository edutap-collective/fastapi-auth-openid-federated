"""Tests for trust chain resolution (navigation only, no signature checks)."""

import httpx
import pytest

from fastapi_auth.openid.federation import jose, trust_chain
from fastapi_auth.openid.federation.errors import TrustChainError


def _build_three_level(federation):
    """TA -> intermediate -> leaf, with fetch endpoints on TA and intermediate."""
    federation.add_entity(
        "https://ta.example",
        fetch_endpoint="https://ta.example/fetch",
        metadata={"federation_entity": {"organization_name": "TA"}},
    )
    federation.add_entity(
        "https://im.example",
        authority_hints=["https://ta.example"],
        fetch_endpoint="https://im.example/fetch",
    )
    federation.add_entity(
        "https://leaf.example",
        authority_hints=["https://im.example"],
        metadata={"openid_provider": {"issuer": "https://leaf.example"}},
    )


@pytest.mark.asyncio
async def test_resolves_leaf_first_chain_to_anchor(federation, mock_router):
    _build_three_level(federation)
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")
    federation.mount_fetch(mock_router, "https://im.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            chain = await trust_chain.resolve_trust_chain(
                client, "https://leaf.example", ["https://ta.example"]
            )

    claims = [jose.peek_claims(t) for t in chain]
    assert claims[0]["iss"] == claims[0]["sub"] == "https://leaf.example"  # leaf EC
    assert claims[1]["iss"] == "https://im.example"  # subordinate about leaf
    assert claims[1]["sub"] == "https://leaf.example"
    assert claims[2]["iss"] == "https://ta.example"  # subordinate about intermediate
    assert claims[2]["sub"] == "https://im.example"
    assert len(chain) == 3


@pytest.mark.asyncio
async def test_resolves_direct_leaf_under_anchor(federation, mock_router):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
    federation.add_entity("https://leaf.example", authority_hints=["https://ta.example"])
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            chain = await trust_chain.resolve_trust_chain(
                client, "https://leaf.example", ["https://ta.example"]
            )
    assert len(chain) == 2
    assert jose.peek_claims(chain[1])["iss"] == "https://ta.example"


@pytest.mark.asyncio
async def test_raises_when_no_branch_reaches_configured_anchor(federation, mock_router):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
    federation.add_entity("https://leaf.example", authority_hints=["https://ta.example"])
    federation.mount(mock_router)
    federation.mount_fetch(mock_router, "https://ta.example")

    with mock_router:
        async with httpx.AsyncClient() as client:
            with pytest.raises(TrustChainError):
                # A different anchor is configured -> chain must not be trusted.
                await trust_chain.resolve_trust_chain(
                    client, "https://leaf.example", ["https://other-ta.example"]
                )
