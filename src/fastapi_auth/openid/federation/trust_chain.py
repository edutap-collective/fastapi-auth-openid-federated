"""Resolve and validate OpenID Federation trust chains (Sections 4, 10).

Resolution walks ``authority_hints`` from the leaf upward, fetching each
superior's Entity Configuration (to locate its federation fetch endpoint) and
then the Subordinate Statement about the entity below it, until it reaches a
*configured* Trust Anchor. Resolution uses unverified ``peek_claims`` purely to
navigate; every statement is cryptographically verified later, in
``validate_trust_chain`` (Task 6).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from fastapi_auth.openid.federation import fetch, jose
from fastapi_auth.openid.federation.errors import FetchError, TrustChainError


async def _walk(
    client: httpx.AsyncClient,
    subject_id: str,
    subject_claims: dict[str, object],
    trust_anchor_ids: frozenset[str],
    visited: frozenset[str],
    depth: int,
) -> list[str] | None:
    """Return subordinate statements from ``subject`` up to a configured anchor."""
    hints = subject_claims.get("authority_hints", [])
    if not isinstance(hints, list):
        return None
    for superior_id in hints:
        if not isinstance(superior_id, str) or superior_id in visited:
            continue
        try:
            superior_ec = await fetch.fetch_entity_configuration(client, superior_id)
        except FetchError:
            continue
        superior_claims = jose.peek_claims(superior_ec)
        endpoint = _fetch_endpoint(superior_claims)
        if endpoint is None:
            continue
        try:
            subordinate = await fetch.fetch_subordinate_statement(client, endpoint, subject_id)
        except FetchError:
            continue
        if superior_id in trust_anchor_ids:
            return [subordinate]
        if depth <= 1:
            continue
        rest = await _walk(
            client,
            superior_id,
            superior_claims,
            trust_anchor_ids,
            visited | {superior_id},
            depth - 1,
        )
        if rest is not None:
            return [subordinate, *rest]
    return None


def _fetch_endpoint(claims: dict[str, object]) -> str | None:
    metadata = claims.get("metadata")
    if not isinstance(metadata, dict):
        return None
    federation_entity = metadata.get("federation_entity")
    if not isinstance(federation_entity, dict):
        return None
    endpoint = federation_entity.get("federation_fetch_endpoint")
    return endpoint if isinstance(endpoint, str) else None


async def resolve_trust_chain(
    client: httpx.AsyncClient,
    leaf_entity_id: str,
    trust_anchor_ids: Sequence[str],
    *,
    max_depth: int = 10,
) -> list[str]:
    """Resolve a leaf-first trust chain terminating at a configured anchor."""
    anchors = frozenset(trust_anchor_ids)
    leaf_ec = await fetch.fetch_entity_configuration(client, leaf_entity_id)
    leaf_claims = jose.peek_claims(leaf_ec)
    tail = await _walk(
        client,
        leaf_entity_id,
        leaf_claims,
        anchors,
        frozenset({leaf_entity_id}),
        max_depth,
    )
    if tail is None:
        raise TrustChainError(
            f"no trust chain from {leaf_entity_id} to a configured trust anchor {sorted(anchors)}"
        )
    return [leaf_ec, *tail]
