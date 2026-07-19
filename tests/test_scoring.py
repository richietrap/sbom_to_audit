from sbom_to_audit.model.scoring import compute_scores


def snapshot(execution=False, reachable=False, vex="known_not_affected"):
    return {
        "identity_resolution": {"gamma_id": 1.0},
        "vulnerability_intelligence": {"cisa_kev_status": False, "epss_percentile": 0.92},
        "supplier_assertions": {"csaf_vex_status": vex},
        "local_evidence": {
            "execution_observed": execution,
            "reachability_confirmed": reachable,
            "telemetry_reference": "telemetry.jsonl",
        },
        "asset_context": {"asset_criticality": "high", "deployment_scope": "limited"},
        "mitigation_context": {"mitigation_status": "none"},
    }


def test_not_affected_without_local_signal_has_low_applicability():
    scores = compute_scores(snapshot(), conflict=False)
    assert scores.A_t == 0.1
    assert scores.E_t == 0.552
    assert scores.I_t == 0.625


def test_runtime_execution_has_strongest_evidence_and_applicability():
    scores = compute_scores(snapshot(execution=True, reachable=True), conflict=True)
    assert scores.E_t == 1.0
    assert scores.A_t == 1.0
    assert scores.C_t is True
