"""Tests for metadata policy merge and application (Section 6.1)."""

from typing import Any, cast

import pytest

from fastapi_auth.openid.federation import metadata_policy as mp
from fastapi_auth.openid.federation.errors import MetadataPolicyError

# --- apply_policy ---


def test_apply_value_overrides():
    out = mp.apply_policy({"a": "x"}, {"a": {"value": "forced"}})
    assert out["a"] == "forced"


def test_apply_value_null_removes_parameter():
    out = mp.apply_policy({"a": "x"}, {"a": {"value": None}})
    assert "a" not in out


def test_apply_default_only_when_missing():
    assert mp.apply_policy({}, {"a": {"default": "d"}})["a"] == "d"
    assert mp.apply_policy({"a": "kept"}, {"a": {"default": "d"}})["a"] == "kept"


def test_apply_add_unions_lists():
    out = mp.apply_policy({"a": ["x"]}, {"a": {"add": ["y", "x"]}})
    assert sorted(cast("list[str]", out["a"])) == ["x", "y"]


def test_apply_subset_of_intersects():
    out = mp.apply_policy({"a": ["x", "y", "z"]}, {"a": {"subset_of": ["x", "z"]}})
    assert sorted(cast("list[str]", out["a"])) == ["x", "z"]


def test_apply_one_of_ok_and_violation():
    assert mp.apply_policy({"a": "x"}, {"a": {"one_of": ["x", "y"]}})["a"] == "x"
    with pytest.raises(MetadataPolicyError, match="one_of"):
        mp.apply_policy({"a": "z"}, {"a": {"one_of": ["x", "y"]}})


def test_apply_superset_of_requires_all():
    assert mp.apply_policy({"a": ["x", "y", "z"]}, {"a": {"superset_of": ["x", "y"]}})["a"]
    with pytest.raises(MetadataPolicyError, match="superset_of"):
        mp.apply_policy({"a": ["x"]}, {"a": {"superset_of": ["x", "y"]}})


def test_apply_essential_missing_raises():
    with pytest.raises(MetadataPolicyError, match="essential"):
        mp.apply_policy({}, {"a": {"essential": True}})


def test_apply_essential_false_missing_is_ok():
    out = mp.apply_policy({}, {"a": {"essential": False}})
    assert "a" not in out


def test_apply_operator_order_value_then_subset():
    # value sets ["x","y"], subset_of keeps ["x"] -> final ["x"]
    out = mp.apply_policy({"a": ["z"]}, {"a": {"value": ["x", "y"], "subset_of": ["x"]}})
    assert out["a"] == ["x"]


# --- merge_policies (TA -> leaf order) ---


def test_merge_value_equal_ok_conflict_raises():
    merged = cast(
        "dict[str, Any]",
        mp.merge_policies([{"op": {"p": {"value": "v"}}}, {"op": {"p": {"value": "v"}}}]),
    )
    assert merged["op"]["p"]["value"] == "v"
    with pytest.raises(MetadataPolicyError, match="value"):
        mp.merge_policies([{"op": {"p": {"value": "a"}}}, {"op": {"p": {"value": "b"}}}])


def test_merge_add_unions():
    merged = cast(
        "dict[str, Any]",
        mp.merge_policies([{"op": {"p": {"add": ["x"]}}}, {"op": {"p": {"add": ["y"]}}}]),
    )
    assert sorted(merged["op"]["p"]["add"]) == ["x", "y"]


def test_merge_one_of_intersects_empty_raises():
    merged = cast(
        "dict[str, Any]",
        mp.merge_policies(
            [{"op": {"p": {"one_of": ["x", "y"]}}}, {"op": {"p": {"one_of": ["y", "z"]}}}]
        ),
    )
    assert merged["op"]["p"]["one_of"] == ["y"]
    with pytest.raises(MetadataPolicyError, match="one_of"):
        mp.merge_policies([{"op": {"p": {"one_of": ["x"]}}}, {"op": {"p": {"one_of": ["z"]}}}])


def test_merge_subset_of_intersects():
    merged = cast(
        "dict[str, Any]",
        mp.merge_policies(
            [
                {"op": {"p": {"subset_of": ["a", "b", "c"]}}},
                {"op": {"p": {"subset_of": ["b", "c", "d"]}}},
            ]
        ),
    )
    assert sorted(merged["op"]["p"]["subset_of"]) == ["b", "c"]


def test_merge_new_entity_types_and_parameters_pass_through():
    merged = cast(
        "dict[str, Any]",
        mp.merge_policies([{"op": {"p": {"value": "v"}}}, {"op2": {"q": {"default": "d"}}}]),
    )
    assert merged["op"]["p"]["value"] == "v"
    assert merged["op2"]["q"]["default"] == "d"


def test_merge_unknown_critical_operator_raises():
    with pytest.raises(MetadataPolicyError, match="critical"):
        mp.merge_policies([{"op": {"p": {"weird_op": 1}}}], critical_operators=["weird_op"])


def test_merge_unknown_non_critical_operator_is_ignored():
    merged = cast(
        "dict[str, Any]", mp.merge_policies([{"op": {"p": {"weird_op": 1, "value": "v"}}}])
    )
    assert merged["op"]["p"]["value"] == "v"
    assert "weird_op" not in merged["op"]["p"]
