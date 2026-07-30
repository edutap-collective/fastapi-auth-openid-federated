"""End-to-end tests: resolve + validate + metadata policy over the in-memory federation."""

import httpx
import pytest

from fastapi_auth.openid.federation import trust_chain

NOW = 1_700_000_000


def _federation_with_policy(federation):
    federation.add_entity(
        "https://ta.example",
        fetch_endpoint="https://ta.example/fetch",
    )
    federation.add_entity(
        "https://im.example",
        authority_hints=["https://ta.example"],
        fetch_endpoint="https://im.example/fetch",
    )
    federation.add_entity(
        "https://op.example",
        authority_hints=["https://im.example"],
        metadata={
            "openid_provider": {
                "issuer": "https://op.example",
                "token_endpoint": "https://op.example/token",
                "grant_types_supported": ["authorization_code", "implicit"],
            }
        },
    )


@pytest.mark.asyncio
async def test_resolve_and_validate_returns_policy_resolved_metadata(federation, mock_router):
    _federation_with_policy(federation)
    federation.mount(mock_router)

    # TA restricts grant types to authorization_code via a subordinate about the intermediate;
    # mount a custom fetch that carries the policy.
    def ta_fetch(request):
        sub = request.url.params["sub"]
        return httpx.Response(
            200,
            text=federation.subordinate(
                "https://ta.example",
                sub,
                metadata_policy={
                    "openid_provider": {
                        "grant_types_supported": {"subset_of": ["authorization_code"]}
                    }
                },
                now=NOW,
            ),
            headers={"content-type": "application/entity-statement+jwt"},
        )

    mock_router.get("https://ta.example/fetch").mock(side_effect=ta_fetch)
    federation.mount_fetch(mock_router, "https://im.example")

    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with mock_router:
        async with httpx.AsyncClient() as client:
            resolved = await trust_chain.resolve_and_validate(
                client, "https://op.example", anchors, now=NOW + 10
            )

    assert resolved.entity_id == "https://op.example"
    assert resolved.metadata["issuer"] == "https://op.example"
    assert resolved.metadata["token_endpoint"] == "https://op.example/token"  # noqa: S105
    # policy applied: implicit removed by subset_of
    assert resolved.metadata["grant_types_supported"] == ["authorization_code"]
    assert resolved.trust_anchor_id == "https://ta.example"


@pytest.mark.asyncio
async def test_resolve_and_validate_policy_violation_invalidates(federation, mock_router):
    _federation_with_policy(federation)
    federation.mount(mock_router)

    def ta_fetch(request):
        sub = request.url.params["sub"]
        return httpx.Response(
            200,
            text=federation.subordinate(
                "https://ta.example",
                sub,
                metadata_policy={
                    "openid_provider": {"issuer": {"value": "https://forced.example"}}
                },
                now=NOW,
            ),
            headers={"content-type": "application/entity-statement+jwt"},
        )

    mock_router.get("https://ta.example/fetch").mock(side_effect=ta_fetch)
    federation.mount_fetch(mock_router, "https://im.example")

    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with mock_router:
        async with httpx.AsyncClient() as client:
            resolved = await trust_chain.resolve_and_validate(
                client, "https://op.example", anchors, now=NOW + 10
            )
    # value operator forces issuer; resolved metadata reflects the policy.
    assert resolved.metadata["issuer"] == "https://forced.example"


def test_cache_respects_expiry(federation):
    _federation_with_policy(federation)
    cache = trust_chain.TrustChainCache()
    chain = trust_chain.ValidatedChain(
        statements=({"sub": "https://op.example", "exp": NOW + 100},),
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
    )
    resolved = trust_chain.ResolvedEntity(
        entity_id="https://op.example",
        entity_type="openid_provider",
        metadata={"issuer": "https://op.example"},
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
        chain=chain,
    )
    cache.set(resolved)
    assert cache.get("https://op.example", now=NOW + 50) is resolved
    assert cache.get("https://op.example", now=NOW + 200) is None  # expired
    assert cache.get("https://unknown.example", now=NOW) is None


def test_resolve_metadata_missing_entity_type_raises(federation):
    from fastapi_auth.openid.federation.errors import TrustChainError

    _federation_with_policy(federation)
    chain = trust_chain.ValidatedChain(
        statements=(
            {
                "iss": "https://op.example",
                "sub": "https://op.example",
                "exp": NOW + 100,
                "metadata": {},
            },
            {"iss": "https://ta.example", "sub": "https://op.example", "exp": NOW + 100},
        ),
        trust_anchor_id="https://ta.example",
        exp=NOW + 100,
    )
    with pytest.raises(TrustChainError, match="openid_provider"):
        trust_chain.resolve_metadata(chain, entity_type="openid_provider")
