import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from sbom_to_audit.model.deadline_engine import (
    DeadlineMilestone,
    deadline_status_audit_event,
    evaluate_deadline,
)
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.model.metrics import MANDATORY_FIELDS
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "evidencepack_v0.2.schema.json"
SCENARIO_PATH = ROOT / "data" / "scenarios" / "ghost_logger.yaml"


def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def build_pack() -> dict[str, Any]:
    scenario = read_yaml(SCENARIO_PATH)
    assert isinstance(scenario, dict)
    pack = replay_scenario(scenario)["pack"]
    assert isinstance(pack, dict)
    return pack


def test_generated_evidencepack_remains_schema_valid() -> None:
    validator().validate(build_pack())


def test_deadline_event_is_valid_inside_unchanged_v02_audit_log() -> None:
    pack = build_pack()
    milestone = DeadlineMilestone("early_warning", 24, 6, 2)
    result = evaluate_deadline(milestone, delta_t_hours=22, applicable=True)
    event = deadline_status_audit_event(
        result,
        event_id="evt-deadline-schema-001",
        timestamp="2026-09-13T06:00:00Z",
        previous_status="Due Soon",
        output_state=pack["decision_state"]["recommended_state"],
        input_references=["clock-start-event", "deadline-profile"],
    )
    amended = deepcopy(pack)
    amended["audit_log"].append(event)
    validator().validate(amended)


def test_schema_and_ec_denominator_remain_locked() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "0.2"
    assert len(MANDATORY_FIELDS) == 34
    assert "deadline_context" not in schema["properties"]
    assert (
        "Breach Imminent"
        not in schema["properties"]["decision_state"]["properties"]["recommended_state"]["enum"]
    )
