from copy import deepcopy
from pathlib import Path

import pytest

from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "ghost_logger.yaml"


def _scenario() -> dict:
    value = read_yaml(SCENARIO)
    assert isinstance(value, dict)
    return value


def test_replay_rejects_out_of_order_events() -> None:
    mutated = deepcopy(_scenario())
    mutated["replay_events"][0], mutated["replay_events"][1] = (
        mutated["replay_events"][1],
        mutated["replay_events"][0],
    )
    with pytest.raises(ValueError, match="replay events must be time-ordered"):
        replay_scenario(mutated, repository_root=ROOT)


def test_replay_rejects_duplicate_event_ids() -> None:
    mutated = deepcopy(_scenario())
    mutated["replay_events"][1]["event_id"] = mutated["replay_events"][0]["event_id"]
    with pytest.raises(ValueError, match="duplicate replay event_id"):
        replay_scenario(mutated, repository_root=ROOT)


def test_replay_rejects_future_dated_source_release() -> None:
    mutated = deepcopy(_scenario())
    mutated["source_catalog"][0]["timestamp"] = "2026-09-12T11:00:00Z"
    with pytest.raises(ValueError, match="releases future-dated source"):
        replay_scenario(mutated, repository_root=ROOT)
