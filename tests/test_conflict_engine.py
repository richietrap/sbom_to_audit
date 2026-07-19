from sbom_to_audit.model.conflict_engine import detect_conflicts


def _claim(claim_id: str, value: object, *, status: str = "active") -> dict:
    return {
        "claim_id": claim_id,
        "proposition": "product_affectedness",
        "value": value,
        "scope": {
            "product_purl": "pkg:generic/p@1.0",
            "component_purl": "pkg:generic/c@1.0",
            "cve_id": "CVE-2026-41001",
        },
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


def test_broad_and_deployment_specific_claims_conflict_when_values_differ() -> None:
    broad = _claim("a", False)
    narrow = _claim("b", True)
    narrow["scope"]["deployment_id"] = "edge-17"
    conflicts = detect_conflicts([broad, narrow])
    assert len(conflicts) == 1
    assert conflicts[0]["scope"]["relation"] == "left_contains_right"


def test_disjoint_product_variants_do_not_conflict() -> None:
    standard = _claim("a", False)
    legacy = _claim("b", True)
    standard["scope"]["product_variant"] = "standard-profile"
    legacy["scope"]["product_variant"] = "legacy-plugin-profile"
    assert detect_conflicts([standard, legacy]) == []


def test_malformed_scope_fails_closed() -> None:
    malformed = _claim("a", False)
    malformed["scope"].pop("component_purl")
    try:
        detect_conflicts([malformed, _claim("b", True)])
    except ValueError as exc:
        assert "missing required identity dimensions" in str(exc)
    else:
        raise AssertionError("malformed claim scope should fail closed")
