"""Deterministic scope-aware conflict detection for normalized evidence claims."""

from __future__ import annotations

from itertools import combinations
from typing import Any

from sbom_to_audit.model.scope import scope_relation, scopes_overlap, validate_scope

ACTIVE_CLAIM_STATUSES = {"active", "confirmed"}


def active_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        claim
        for claim in claims
        if str(claim.get("status") or "active").strip().lower() in ACTIVE_CLAIM_STATUSES
    ]


def detect_conflicts(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect incompatible active claims whose scopes overlap.

    Omitted optional dimensions are broad constraints rather than exact-string
    mismatches. Claims with conflicting specified dimensions are disjoint and do
    not form a conflict. Each contradictory pair is emitted deterministically.
    """

    by_proposition: dict[str, list[dict[str, Any]]] = {}
    for claim in active_claims(claims):
        proposition = str(claim.get("proposition") or "").strip()
        if proposition:
            by_proposition.setdefault(proposition, []).append(claim)

    conflicts: list[dict[str, Any]] = []
    for proposition, proposition_claims in sorted(by_proposition.items()):
        ordered = sorted(proposition_claims, key=lambda item: str(item.get("claim_id") or ""))
        for left, right in combinations(ordered, 2):
            if repr(left.get("value")) == repr(right.get("value")):
                continue
            left_scope = validate_scope(left.get("scope") or {})
            right_scope = validate_scope(right.get("scope") or {})
            if not scopes_overlap(left_scope, right_scope):
                continue
            relation = scope_relation(left_scope, right_scope).value
            conflicts.append(
                {
                    "conflict_id": f"CONFLICT-{len(conflicts) + 1:03d}",
                    "proposition": proposition,
                    "scope": {
                        "left": left_scope,
                        "right": right_scope,
                        "relation": relation,
                    },
                    "scope_key": repr((left_scope, right_scope, relation)),
                    "claim_ids": [str(left["claim_id"]), str(right["claim_id"])],
                    "values": [left.get("value"), right.get("value")],
                    "sources": [
                        left.get("source_artifact_id"),
                        right.get("source_artifact_id"),
                    ],
                    "status": "active",
                }
            )
    return conflicts
