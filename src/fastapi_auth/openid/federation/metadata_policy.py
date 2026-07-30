"""Merge and apply OpenID Federation metadata policies (Section 6.1).

A metadata policy is a three-level mapping ``entity_type -> parameter ->
operator -> value``. Policies from the trust chain are merged top-down
(Trust Anchor first, leaf's immediate superior last); the merged policy is then
applied to the leaf's metadata for one entity type. Operators are applied in the
fixed order ``value, add, default, one_of, subset_of, superset_of, essential``.

Once a policy has constrained a parameter, a more subordinate policy may only
constrain it further, never relax it — conflicting merges make the whole trust
chain invalid (Section 6.1.1).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from fastapi_auth.openid.federation.errors import MetadataPolicyError

KNOWN_OPERATORS: frozenset[str] = frozenset(
    {"value", "add", "default", "one_of", "subset_of", "superset_of", "essential"}
)
APPLICATION_ORDER: tuple[str, ...] = (
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
)

_MISSING = object()


def _as_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else [value]


def _union(left: object, right: object) -> list[object]:
    result = list(_as_list(left))
    for item in _as_list(right):
        if item not in result:
            result.append(item)
    return result


def _intersect(left: object, right: object) -> list[object]:
    right_list = _as_list(right)
    return [item for item in _as_list(left) if item in right_list]


# --- merge -------------------------------------------------------------------


def _merge_operator(operator: str, current: object, incoming: object) -> object:
    if operator in {"value", "default"}:
        if current != incoming:
            raise MetadataPolicyError(
                f"conflicting {operator!r} on merge: {current!r} != {incoming!r}"
            )
        return current
    if operator in {"add", "superset_of"}:
        return _union(current, incoming)
    if operator == "one_of":
        merged = _intersect(current, incoming)
        if not merged:
            raise MetadataPolicyError("merging one_of produced an empty set")
        return merged
    if operator == "subset_of":
        return _intersect(current, incoming)
    if operator == "essential":
        return bool(current) or bool(incoming)
    raise MetadataPolicyError(f"cannot merge unknown operator {operator!r}")


def _merge_parameter(
    current: dict[str, object],
    incoming: dict[str, object],
    critical: frozenset[str],
) -> dict[str, object]:
    merged = dict(current)
    for operator, value in incoming.items():
        if operator not in KNOWN_OPERATORS:
            if operator in critical:
                raise MetadataPolicyError(f"unknown critical policy operator {operator!r}")
            continue  # unknown, non-critical -> ignore
        if operator in merged:
            merged[operator] = _merge_operator(operator, merged[operator], value)
        else:
            merged[operator] = value
    return merged


def merge_policies(
    policies: Sequence[dict[str, object]],
    *,
    critical_operators: Sequence[str] = (),
) -> dict[str, object]:
    """Merge a chain of metadata policies (ordered Trust Anchor -> leaf)."""
    critical = frozenset(critical_operators)
    merged: dict[str, object] = {}
    for policy in policies:
        for entity_type, params in policy.items():
            if not isinstance(params, dict):
                raise MetadataPolicyError(f"policy for {entity_type!r} is not an object")
            entity_bucket = dict(cast("dict[str, object]", merged.get(entity_type, {})))
            for parameter, operators in cast("dict[str, object]", params).items():
                if not isinstance(operators, dict):
                    raise MetadataPolicyError(
                        f"policy for {entity_type}.{parameter} is not an object"
                    )
                entity_bucket[parameter] = _merge_parameter(
                    cast("dict[str, object]", entity_bucket.get(parameter, {})),
                    cast("dict[str, object]", operators),
                    critical,
                )
            merged[entity_type] = entity_bucket
    return merged


# --- apply -------------------------------------------------------------------


def _apply_operator(operator: str, spec: object, value: object, parameter: str) -> object:
    if operator == "value":
        return _MISSING if spec is None else spec
    if operator == "add":
        base = value if value is not _MISSING else []
        return _union(base, spec)
    if operator == "default":
        return spec if value is _MISSING else value
    if operator == "one_of":
        if value is _MISSING:
            return value
        if value not in _as_list(spec):
            raise MetadataPolicyError(f"{parameter}: value {value!r} not in one_of {spec!r}")
        return value
    if operator == "subset_of":
        if value is _MISSING:
            return value
        return _intersect(value, spec)
    if operator == "superset_of":
        if value is _MISSING:
            return value
        missing = [item for item in _as_list(spec) if item not in _as_list(value)]
        if missing:
            raise MetadataPolicyError(f"{parameter}: value missing superset_of members {missing!r}")
        return value
    if operator == "essential":
        if spec and value is _MISSING:
            raise MetadataPolicyError(f"{parameter}: essential parameter is absent")
        return value
    raise MetadataPolicyError(f"cannot apply unknown operator {operator!r}")


def apply_policy(metadata: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    """Apply one entity type's parameter policies to a metadata dict."""
    result = dict(metadata)
    for parameter, raw_operators in policy.items():
        if not isinstance(raw_operators, dict):
            raise MetadataPolicyError(f"policy for {parameter!r} is not an object")
        operators = cast("dict[str, object]", raw_operators)
        value: object = result.get(parameter, _MISSING)
        for operator in APPLICATION_ORDER:
            if operator in operators:
                value = _apply_operator(operator, operators[operator], value, parameter)
        if value is _MISSING:
            result.pop(parameter, None)
        elif value is None:
            raise MetadataPolicyError(f"{parameter}: policy produced a null value")
        else:
            result[parameter] = value
    return result
