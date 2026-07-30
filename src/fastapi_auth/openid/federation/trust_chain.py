"""Resolve and validate OpenID Federation trust chains (Sections 4, 10).

Resolution walks ``authority_hints`` from the leaf upward, fetching each
superior's Entity Configuration (to locate its federation fetch endpoint) and
then the Subordinate Statement about the entity below it, until it reaches a
*configured* Trust Anchor. Resolution uses unverified ``peek_claims`` purely to
navigate; every statement is cryptographically verified later, in
``validate_trust_chain``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

import httpx

from fastapi_auth.openid.federation import entity_statement as es
from fastapi_auth.openid.federation import fetch, jose
from fastapi_auth.openid.federation.errors import EntityStatementError, FetchError, TrustChainError


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


@dataclass(frozen=True)
class ValidatedChain:
    """A cryptographically validated trust chain (leaf-first)."""

    statements: tuple[dict[str, object], ...]
    trust_anchor_id: str
    exp: int

    @property
    def leaf(self) -> dict[str, object]:
        """Return the leaf's verified Entity Configuration claims."""
        return self.statements[0]

    @property
    def subordinate_statements(self) -> tuple[dict[str, object], ...]:
        """Return all verified statements except the leaf Entity Configuration."""
        return self.statements[1:]


def _keyset_from_statement(claims: dict[str, object]) -> jose.KeySet:
    """Load the ``jwks`` claim of an (unverified) statement as a KeySet."""
    jwks = claims.get("jwks")
    if not isinstance(jwks, dict):
        raise TrustChainError("entity statement has no usable jwks")
    return jose.load_keyset(cast("dict[str, object]", jwks))


def validate_trust_chain(
    chain: Sequence[str],
    trust_anchors: Mapping[str, dict[str, object]],
    *,
    algorithms: Sequence[str] = jose.DEFAULT_SIGNING_ALGORITHMS,
    leeway: int = 0,
    now: int | None = None,
) -> ValidatedChain:
    """Validate every signature, linkage, freshness and the anchor (Section 10.2)."""
    if not chain:
        raise TrustChainError("empty trust chain")

    peeked = [jose.peek_claims(token) for token in chain]
    for claims in peeked:
        try:
            es.check_structure(claims)
            es.check_time(claims, leeway=leeway, now=now)
        except EntityStatementError as exc:
            # Structural/freshness failures are chain-validation failures here,
            # distinct from the SignatureError raised for bad/mismatched keys.
            raise TrustChainError(str(exc)) from exc

    # Leaf must be self-issued.
    if peeked[0].get("iss") != peeked[0].get("sub"):
        raise TrustChainError("leaf entity configuration is not self-issued")

    # Issuer/subject linkage: chain[j].iss == chain[j+1].sub.
    for j in range(len(chain) - 1):
        if peeked[j].get("iss") != peeked[j + 1].get("sub"):
            raise TrustChainError(
                f"broken issuer/subject linkage at position {j}: "
                f"{peeked[j].get('iss')!r} != {peeked[j + 1].get('sub')!r}"
            )

    # Signatures for j = 0..n-2: chain[j] verified with the key set from chain[j+1].jwks.
    verified: list[dict[str, object]] = []
    for j in range(len(chain) - 1):
        keyset = _keyset_from_statement(peeked[j + 1])
        verified.append(
            es.verify_statement(chain[j], keyset, algorithms=algorithms, leeway=leeway, now=now)
        )

    # Top statement (issued by the Trust Anchor) verified with configured anchor keys.
    top_claims = peeked[-1]
    anchor_id = top_claims.get("iss")
    if not isinstance(anchor_id, str) or anchor_id not in trust_anchors:
        raise TrustChainError(
            f"trust chain does not terminate at a configured trust anchor "
            f"(top issuer: {anchor_id!r})"
        )
    anchor_keyset = jose.load_keyset(trust_anchors[anchor_id])
    verified.append(
        es.verify_statement(chain[-1], anchor_keyset, algorithms=algorithms, leeway=leeway, now=now)
    )

    chain_exp = min(cast(int, claims["exp"]) for claims in verified)
    return ValidatedChain(
        statements=tuple(verified),
        trust_anchor_id=anchor_id,
        exp=chain_exp,
    )
