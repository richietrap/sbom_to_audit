from sbom_to_audit.model.conflict_engine import detect_conflicts


def _claim(claim_id: str, value: object, *, status: str = "active") -> dict:
    return {
        "claim_id": claim_id,
        "proposition": "product_affectedness",
        "value": value,
        "scope": {"product": "p", "cve": "CVE-2026-41001"},
        "status": status,
        "source_artifact_id": f"source-{claim_id}",
    }


def test_active_cross_source_contradiction_is_detected() -> None:
    conflicts = detect_conflicts([_claim("a", False), _claim("b", True)])
    assert len(conflicts) == 1
    assert conflicts[0]["claim_ids"] == ["a", "b"]


def test_superseded_claim_is_not_active_conflict() -> None:
    conflicts = detect_conflicts([_claim("a", False, status="superseded"), _claim("b", True)])
    assert conflicts == []
