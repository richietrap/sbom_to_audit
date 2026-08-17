import json

import pytest

from sbom_to_audit.baseline.manual_admission import (
    admit_controlled_exception,
)

ZERO_RELEASE_ERROR = (
    "events without source-access records: "
    "[('rapid_pivot', 'EVT-RP-012H'), "
    "('rapid_pivot', 'EVT-RP-018H'), "
    "('rapid_pivot_control', 'EVT-RPC-018H'), "
    "('rapid_pivot_control', 'EVT-RPC-020H')]"
)


def adjudication():
    return {
        "status": "PASS_WITH_CONTROLLED_ZERO_RELEASE_EVENT_EXCEPTION",
        "controlled_exception_final": True,
        "analyst_clarification_received": True,
        "analyst_clarification_result": (
            "NO_REGISTERED_EVIDENCE_ARTEFACT_REOPENED_FOR_ALL_FOUR_ZERO_RELEASE_EVENTS"
        ),
        "canonical_log_amendment_required": False,
    }


def test_exact_controlled_exception_is_admitted(tmp_path):
    path = tmp_path / "adjudication.json"
    path.write_text(json.dumps(adjudication()))

    result = admit_controlled_exception(
        [ZERO_RELEASE_ERROR],
        path,
        expected_errors=[ZERO_RELEASE_ERROR],
        expected_adjudication=adjudication(),
        basis="CONTROLLED_ZERO_RELEASE_EVENT_EXCEPTION",
    )

    assert result["admitted"] is True
    assert result["strict_validation_valid"] is False
    assert result["strict_validation_errors"] == [ZERO_RELEASE_ERROR]
    assert result["basis"] == "CONTROLLED_ZERO_RELEASE_EVENT_EXCEPTION"


def test_different_validation_error_is_rejected(tmp_path):
    path = tmp_path / "adjudication.json"
    path.write_text(json.dumps(adjudication()))

    with pytest.raises(
        ValueError,
        match="validation errors do not match",
    ):
        admit_controlled_exception(
            ["some other validation failure"],
            path,
            expected_errors=[ZERO_RELEASE_ERROR],
            expected_adjudication=adjudication(),
            basis="CONTROLLED_ZERO_RELEASE_EVENT_EXCEPTION",
        )


def test_tampered_adjudication_is_rejected(tmp_path):
    payload = adjudication()
    payload["controlled_exception_final"] = False

    path = tmp_path / "adjudication.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(
        ValueError,
        match="controlled-exception adjudication mismatch",
    ):
        admit_controlled_exception(
            [ZERO_RELEASE_ERROR],
            path,
            expected_errors=[ZERO_RELEASE_ERROR],
            expected_adjudication=adjudication(),
            basis="CONTROLLED_ZERO_RELEASE_EVENT_EXCEPTION",
        )
