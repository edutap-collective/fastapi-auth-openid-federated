"""Adversarial tests for trust chain validation."""

from typing import cast

import pytest

from fastapi_auth.openid.federation import jose, trust_chain
from fastapi_auth.openid.federation.errors import SignatureError, TrustChainError

NOW = 1_700_000_000


def _three_level(federation):
    federation.add_entity("https://ta.example", fetch_endpoint="https://ta.example/fetch")
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


def _valid_chain(federation) -> list[str]:
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    sub_about_leaf = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    return [leaf_ec, sub_about_leaf, sub_about_im]


def test_valid_chain_passes(federation):
    _three_level(federation)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    result = trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)
    assert result.trust_anchor_id == "https://ta.example"
    assert result.leaf["sub"] == "https://leaf.example"
    assert result.exp == min(cast(int, s["exp"]) for s in result.statements)


def test_rejects_chain_not_ending_at_configured_anchor(federation):
    _three_level(federation)
    anchors = {"https://other.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="configured trust anchor"):
        trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)


def test_rejects_forged_subordinate_signature(federation):
    from fastapi_auth.openid.federation import entity_statement as es

    _three_level(federation)
    federation.add_entity("https://attacker.example")
    leaf = federation.entities["https://leaf.example"]
    attacker = federation.entities["https://attacker.example"]
    # Keep the linkage valid (iss=im, sub=leaf, jwks=leaf keys) so we reach the
    # signature check, but sign with the ATTACKER's key instead of the intermediate's.
    claims = es.build_subordinate_statement(
        issuer="https://im.example",
        subject="https://leaf.example",
        jwks=leaf.public_jwks(),
        now=NOW,
    )
    forged = jose.sign_entity_statement(claims, attacker.key)
    leaf_ec = leaf.entity_configuration(now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    chain = [leaf_ec, forged, sub_about_im]
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    # forged is verified against chain[2].jwks (the intermediate's keys) -> no matching kid.
    with pytest.raises(SignatureError):
        trust_chain.validate_trust_chain(chain, anchors, now=NOW + 10)


def test_rejects_tampered_ta_key(federation):
    _three_level(federation)
    federation.add_entity("https://impostor.example")
    # Configure the correct anchor id but with the WRONG public keys.
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://impostor.example")}
    with pytest.raises(SignatureError):
        trust_chain.validate_trust_chain(_valid_chain(federation), anchors, now=NOW + 10)


def test_rejects_broken_issuer_subject_linkage(federation):
    _three_level(federation)
    federation.add_entity("https://rogue.example", fetch_endpoint="https://rogue.example/fetch")
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    # subordinate about a DIFFERENT subject than the leaf ->
    # linkage break at chain[0].iss vs chain[1].sub
    sub_about_rogue = federation.subordinate("https://im.example", "https://rogue.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="linkage"):
        trust_chain.validate_trust_chain(
            [leaf_ec, sub_about_rogue, sub_about_im], anchors, now=NOW + 10
        )


def test_rejects_expired_statement(federation):
    _three_level(federation)
    leaf_ec = federation.entities["https://leaf.example"].entity_configuration(now=NOW)
    sub_about_leaf = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="expired"):
        # Far in the future -> every statement's exp is in the past.
        trust_chain.validate_trust_chain(
            [leaf_ec, sub_about_leaf, sub_about_im], anchors, now=NOW + 100_000
        )


def test_rejects_leaf_that_is_not_self_issued(federation):
    _three_level(federation)
    # Use a subordinate statement (iss != sub) in the leaf slot.
    not_self = federation.subordinate("https://im.example", "https://leaf.example", now=NOW)
    sub_about_im = federation.subordinate("https://ta.example", "https://im.example", now=NOW)
    anchors = {"https://ta.example": federation.trust_anchor_keys("https://ta.example")}
    with pytest.raises(TrustChainError, match="self-issued"):
        trust_chain.validate_trust_chain([not_self, sub_about_im], anchors, now=NOW + 10)
