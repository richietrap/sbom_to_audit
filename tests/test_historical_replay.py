from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from sbom_to_audit.historical.public_replay import run_public_historical_replay
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "data/historical_replays/cve_2024_3400/public_source_registry.yaml"
CHRONOLOGY = ROOT / "data/historical_replays/cve_2024_3400/chronology.yaml"


def test_public_replay_has_explicit_evidence_boundary() -> None:
    result = run_public_historical_replay(ROOT)
    bundle = result["bundle"]
    assert bundle["classification"] == "HISTORICAL_PUBLIC_REPLAY"
    assert bundle["evidence_boundaries"]["full_evidencepack_generated"] is False
    assert bundle["evidence_boundaries"]["organisation_local_reachability"] == "unavailable"
    assert bundle["evidence_boundaries"]["human_authorization"] == "unavailable"
    assert bundle["source_manifest"]["source_count"] == 7
    assert len(bundle["timeline"]) == 8


def test_occurrence_time_does_not_create_public_knowledge_before_publication() -> None:
    result = run_public_historical_replay(ROOT)
    timeline = result["bundle"]["timeline"]
    assert timeline[0]["available_source_ids"] == []
    assert timeline[1]["available_source_ids"] == []
    assert timeline[2]["available_source_ids"] == []
    assert timeline[3]["public_exploitation_known"] is False
    assert timeline[4]["public_exploitation_known"] is True


def test_offline_replay_retains_required_online_gate_blocker() -> None:
    bundle = run_public_historical_replay(ROOT)["bundle"]
    assert bundle["provisional_source_ids"] == []
    assert bundle["epss_verification_contract_source_ids"] == ["HIST-EPSS-001"]
    assert bundle["historical_epss_verification"]["status"] == (
        "verification_contract_valid_online_gate_required"
    )
    assert bundle["manuscript_eligibility"] is False
    assert bundle["evaluation_status"] == "PILOT_VERIFICATION_CANDIDATE"
    assert bundle["eligibility_blockers"]


def test_public_replay_is_deterministic() -> None:
    assert run_public_historical_replay(ROOT) == run_public_historical_replay(ROOT)


def test_temporal_leakage_is_rejected(tmp_path: Path) -> None:
    registry = read_yaml(REGISTRY)
    chronology = read_yaml(CHRONOLOGY)
    assert isinstance(registry, dict) and isinstance(chronology, dict)
    copied_root = tmp_path / "repo"
    copied_root.mkdir()
    # Use absolute source paths through a copied registry is forbidden, so copy the historical tree.
    target = copied_root / "data/historical_replays/cve_2024_3400"
    target.mkdir(parents=True)
    import shutil

    shutil.copytree(REGISTRY.parent / "public_sources", target / "public_sources")
    (target / "public_source_registry.yaml").write_text(REGISTRY.read_text())
    mutated = deepcopy(chronology)
    mutated["events"][3]["release_source_ids"] = ["HIST-VOLEXITY-001"]
    (target / "chronology.yaml").write_text(__import__("yaml").safe_dump(mutated, sort_keys=False))
    with pytest.raises(ValueError, match="temporal leakage"):
        run_public_historical_replay(copied_root)
