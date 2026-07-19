"""Canonical claim-scope normalization and overlap reasoning."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

IDENTITY_DIMENSIONS = ("product_purl", "component_purl", "cve_id")
OPTIONAL_DIMENSIONS = ("product_variant", "deployment_id", "environment")
SCOPE_DIMENSIONS = IDENTITY_DIMENSIONS + OPTIONAL_DIMENSIONS


class ScopeRelation(str, Enum):
    """Relationship between two normalized evidence scopes."""

    EXACT = "exact"
    LEFT_CONTAINS_RIGHT = "left_contains_right"
    RIGHT_CONTAINS_LEFT = "right_contains_left"
    OVERLAP = "overlap"
    DISJOINT = "disjoint"


def canonicalize_scope(scope: Mapping[str, Any] | None) -> dict[str, str]:
    """Return a deterministic scope containing known, non-empty dimensions only."""

    source = scope or {}
    normalized: dict[str, str] = {}
    for key in SCOPE_DIMENSIONS:
        value = source.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            normalized[key] = text
    return normalized


def validate_scope(scope: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize a claim scope and require all identity dimensions.

    Missing identity keys usually indicate a misspelling or malformed parser
    output. Failing closed avoids accidental product-wide conflicts.
    """

    normalized = canonicalize_scope(scope)
    missing = [key for key in IDENTITY_DIMENSIONS if key not in normalized]
    if missing:
        raise ValueError(f"claim scope missing required identity dimensions: {missing}")
    return normalized


def scope_relation(
    left: Mapping[str, Any] | None, right: Mapping[str, Any] | None
) -> ScopeRelation:
    """Classify two scopes using exact identity and wildcard-like omitted dimensions.

    A specified dimension constrains a scope. An omitted optional dimension is broad,
    not unknown. Conflicting values on any shared dimension make scopes disjoint.
    """

    lhs = validate_scope(left)
    rhs = validate_scope(right)
    shared = set(lhs).intersection(rhs)
    if any(lhs[key] != rhs[key] for key in shared):
        return ScopeRelation.DISJOINT
    if lhs == rhs:
        return ScopeRelation.EXACT

    lhs_keys = set(lhs)
    rhs_keys = set(rhs)
    if lhs_keys < rhs_keys:
        return ScopeRelation.LEFT_CONTAINS_RIGHT
    if rhs_keys < lhs_keys:
        return ScopeRelation.RIGHT_CONTAINS_LEFT
    return ScopeRelation.OVERLAP


def scopes_overlap(left: Mapping[str, Any] | None, right: Mapping[str, Any] | None) -> bool:
    """Return whether two scopes can refer to the same deployment context."""

    return scope_relation(left, right) is not ScopeRelation.DISJOINT


def assertion_applies(
    assertion_scope: Mapping[str, Any] | None,
    target_scope: Mapping[str, Any] | None,
) -> bool:
    """Return whether an assertion's constraints include the target scope."""

    assertion = validate_scope(assertion_scope)
    target = validate_scope(target_scope)
    for key, value in assertion.items():
        if target.get(key) != value:
            return False
    return True
