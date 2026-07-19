import json
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from sbom_to_audit.model.deadline_engine import (
    DeadlineMilestone,
    deadline_status_audit_event,
    evaluate_deadline,
)
from sbom_to_audit.model.metrics import MANDATORY_FIELDS


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "evidencepack_v0.2.schema.json"
PACK_PATH = ROOT / "outputs" / "evidence_packs" / "ghost_logger.json"


def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_existing_evidencepack_remains_schema_valid():
    pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    validator().validate(pack)


def test_deadline_event_is_valid_inside_unchanged_v02_audit_log():
    pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
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


def test_schema_and_ec_denominator_remain_locked():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "0.2"
    assert len(MANDATORY_FIELDS) == 34
    assert "deadline_context" not in schema["properties"]
    assert "Breach Imminent" not in schema["properties"]["decision_state"]["properties"][
        "recommended_state"
    ]["enum"]
