from copy import deepcopy

from sbom_to_audit.model.metrics import (
    MANDATORY_FIELDS,
    evidence_completeness,
    traceability_ratio,
)


def complete_pack():
    return {
        "case_metadata": {
            "case_id": "c",
            "generated_at": "t",
            "clock_start_time": "t",
            "delta_t_hours": 0,
        },
        "product_context": {
            "product_id": "p",
            "product_version": "1",
            "purl": "pkg:x/y@1",
            "sbom_reference": "s",
        },
        "identity_resolution": {
            "primary_identifier": "pkg:x/y@1",
            "matching_method": "exact_versioned_purl",
            "gamma_id": 1.0,
        },
        "vulnerability_intelligence": {
            "cve_id": "CVE-2026-10000",
            "cisa_kev_status": False,
            "epss_percentile": 0.0,
        },
        "supplier_assertions": {"csaf_vex_status": "known_not_affected", "csaf_reference": "v"},
        "local_evidence": {
            "execution_observed": False,
            "reachability_confirmed": False,
            "telemetry_reference": "t",
        },
        "asset_context": {"asset_criticality": "low", "deployment_scope": "isolated"},
        "mitigation_context": {"mitigation_status": "none"},
        "orchestration_metrics": {"E_t": 0, "A_t": 0, "I_t": 0, "M_t": 0, "U_t": 0, "C_t": False},
        "decision_state": {
            "recommended_state": "Monitor",
            "human_authorization_required": True,
            "rationale": "r",
        },
        "claims": [{"claim_id": "1"}],
        "source_artifacts": [{"artifact_id": "1"}],
        "audit_log": [{"event_id": "1"}],
    }


def test_exactly_34_mandatory_fields():
    assert len(MANDATORY_FIELDS) == 34


def test_false_and_zero_count_as_populated():
    assert evidence_completeness(complete_pack()) == 1.0


def test_missing_field_reduces_ec_by_one_thirty_fourth():
    pack = deepcopy(complete_pack())
    pack["product_context"]["purl"] = None
    assert evidence_completeness(pack) == round(33 / 34, 6)


def test_traceability_requires_all_five_fields():
    traceable = {
        "source_artifact_id": "a",
        "source_uri": "file:x",
        "source_hash": "0" * 64,
        "timestamp": "2026-01-01T00:00:00Z",
        "confidence": 0.0,
    }
    incomplete = {**traceable, "source_hash": ""}
    assert traceability_ratio([traceable, incomplete]) == 0.5
