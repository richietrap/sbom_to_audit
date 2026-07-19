from copy import deepcopy

import pytest

from sbom_to_audit.model.scoring import compute_scores


def snapshot(
    execution=False,
    reachable=False,
    vex="known_not_affected",
    kev=False,
    epss=0.92,
):
    return {
        "identity_resolution": {"gamma_id": 1.0},
        "vulnerability_intelligence": {
            "cisa_kev_status": kev,
            "epss_percentile": epss,
        },
        "supplier_assertions": {"csaf_vex_status": vex},
        "local_evidence": {
            "execution_observed": execution,
            "reachability_confirmed": reachable,
            "telemetry_reference": "telemetry.jsonl",
        },
        "asset_context": {
            "asset_criticality": "high",
            "deployment_scope": "limited",
        },
        "mitigation_context": {"mitigation_status": "none"},
    }


def malicious_claim(status="active", traceable=True):
    claim = {
        "claim_id": "claim-malicious-exploitation",
        "proposition": "malicious_exploitation_observed",
        "value": True,
        "source_artifact_id": "telemetry-001",
        "source_uri": "file:data/telemetry/observed.jsonl",
        "source_hash": "a" * 64,
        "timestamp": "2026-09-12T18:00:00Z",
        "confidence": 0.95,
        "status": status,
    }
    if not traceable:
        claim["source_hash"] = ""
    return claim


def test_not_affected_without_local_signal_has_low_applicability():
    scores = compute_scores(snapshot(), conflict=False)
    assert scores.A_t == 0.1
    assert scores.E_t == 0.552
    assert scores.I_t == 0.625


def test_runtime_execution_increases_applicability_not_exploitation():
    scores = compute_scores(
        snapshot(execution=True, reachable=True),
        conflict=True,
    )
    assert scores.A_t == 1.0
    assert scores.E_t == 0.552
    assert scores.C_t is True


def test_traceable_active_malicious_exploitation_is_strongest_E_t_signal():
    scores = compute_scores(
        snapshot(execution=False, reachable=False, kev=False, epss=0.1),
        conflict=False,
        claims=[malicious_claim()],
    )
    assert scores.E_t == 1.0
    assert scores.A_t == 0.1


def test_superseded_or_untraceable_malicious_claim_does_not_raise_E_t():
    base = snapshot(kev=False, epss=0.1)
    superseded = compute_scores(base, conflict=False, claims=[malicious_claim(status="superseded")])
    untraceable = compute_scores(base, conflict=False, claims=[malicious_claim(traceable=False)])
    assert superseded.E_t == 0.06
    assert untraceable.E_t == 0.06


def test_kev_is_vulnerability_level_exploitation_evidence():
    scores = compute_scores(snapshot(kev=True, epss=0.99), conflict=False)
    assert scores.E_t == 0.85


def test_epss_remains_predictive_context_only():
    scores = compute_scores(snapshot(kev=False, epss=0.5), conflict=False)
    assert scores.E_t == 0.3


def test_missing_evidence_is_distinct_from_explicit_false_via_uncertainty():
    explicit_false = snapshot(kev=False, epss=0.5)
    missing = deepcopy(explicit_false)
    missing["vulnerability_intelligence"]["cisa_kev_status"] = None
    missing["local_evidence"]["execution_observed"] = None

    explicit_scores = compute_scores(explicit_false, conflict=False)
    missing_scores = compute_scores(missing, conflict=False)

    assert missing_scores.U_t > explicit_scores.U_t
    assert missing_scores.E_t == explicit_scores.E_t


def test_missing_gamma_id_is_rejected_instead_of_invented():
    incomplete = snapshot()
    incomplete["identity_resolution"]["gamma_id"] = None
    with pytest.raises(ValueError, match="gamma_id"):
        compute_scores(incomplete, conflict=False)
