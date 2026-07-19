"""Deterministic conflict detection for active normalized evidence claims."""

from __future__ import annotations

from typing import Any

ACTIVE_CLAIM_STATUSES = {"active", "confirmed"}


def active_claims(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        claim
        for claim in claims
        if str(claim.get("status") or "active").strip().lower() in ACTIVE_CLAIM_STATUSES
    ]


def detect_conflicts(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect incompatible active values for the same proposition and scope.

    Prototype Stage 2 uses exact proposition and serialized scope equality. The
    limitation is explicit: semantic ontology and interval reasoning are deferred
    to the later generalized conflict engine.
    """

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for claim in active_claims(claims):
        proposition = str(claim.get("proposition") or "")
        scope = repr(claim.get("scope") or {})
        grouped.setdefault((proposition, scope), []).append(claim)

    conflicts: list[dict[str, Any]] = []
    for (proposition, scope), proposition_claims in sorted(grouped.items()):
        normalized = {repr(claim.get("value")) for claim in proposition_claims}
        if len(normalized) <= 1:
            continue
        conflicts.append(
            {
                "conflict_id": f"CONFLICT-{len(conflicts) + 1:03d}",
                "proposition": proposition,
                "scope": proposition_claims[0].get("scope") or {},
                "scope_key": scope,
                "claim_ids": [str(claim["claim_id"]) for claim in proposition_claims],
                "values": [claim.get("value") for claim in proposition_claims],
                "sources": [claim.get("source_artifact_id") for claim in proposition_claims],
                "status": "active",
            }
        )
    return conflicts
