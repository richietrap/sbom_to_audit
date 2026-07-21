from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from sbom_to_audit.historical.epss_ablation import run_epss_ablation
from sbom_to_audit.historical.epss_verification import (
    ARCHIVE_COMMIT,
    EXPECTED_MODEL_VERSION,
    TARGET_CVE,
    TARGET_DATE,
    HistoricalEpssVerificationError,
    parse_api_payload,
    parse_archive_payload,
    verify_offline_contract,
    verify_payloads,
)
from sbom_to_audit.historical.public_replay import run_public_historical_replay

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data/historical_replays/cve_2024_3400/epss/verification_manifest.json"


def _api(epss: str = "0.003710000", percentile: str = "0.723430000") -> bytes:
    return json.dumps(
        {
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "access": "public",
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": TARGET_CVE,
                    "epss": epss,
                    "percentile": percentile,
                    "date": TARGET_DATE,
                }
            ],
        }
    ).encode()


def _archive(
    epss: str = "0.003710000",
    percentile: str = "0.723430000",
    model: str = EXPECTED_MODEL_VERSION,
    date: str = TARGET_DATE,
) -> bytes:
    text = (
        f"#model_version:{model},score_date:{date}T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-3399,0.001,0.100\n"
        f"{TARGET_CVE},{epss},{percentile}\n"
    )
    return gzip.compress(text.encode())


def test_offline_verification_contract_is_valid_and_pinned() -> None:
    result = verify_offline_contract(MANIFEST)
    assert result.status == "offline_contract_valid_online_verification_required"
    assert result.archive_commit == ARCHIVE_COMMIT
    assert all(result.checks.values())


def test_api_and_archive_dual_source_verification_agree() -> None:
    result = verify_payloads(_api(), _archive())
    assert result.status == "authoritative_dual_source_verified"
    assert result.api_record == {
        "cve": TARGET_CVE,
        "date": TARGET_DATE,
        "epss": "0.00371",
        "percentile": "0.72343",
    }
    assert result.archive_record["model_version"] == EXPECTED_MODEL_VERSION
    assert result.api_sha256 and result.archive_sha256 and result.extracted_row_sha256
    assert all(result.checks.values())


def test_epss_or_percentile_disagreement_fails_closed() -> None:
    with pytest.raises(HistoricalEpssVerificationError, match="verification failed") as epss:
        verify_payloads(_api(epss="0.95"), _archive())
    assert epss.value.result.status == "verification_failed"
    assert epss.value.result.api_record == {
        "cve": TARGET_CVE,
        "date": TARGET_DATE,
        "epss": "0.95",
        "percentile": "0.72343",
    }
    assert epss.value.result.checks["api_archive_epss_agree"] is False
    assert epss.value.result.checks["normalized_epss_matches"] is False

    with pytest.raises(HistoricalEpssVerificationError, match="verification failed") as percentile:
        verify_payloads(_api(percentile="0.99"), _archive())
    assert percentile.value.result.archive_record is not None
    assert percentile.value.result.checks["api_archive_percentile_agree"] is False
    assert percentile.value.result.checks["normalized_percentile_matches"] is False


def test_archive_model_and_date_mismatch_fail_closed() -> None:
    with pytest.raises(ValueError, match="model mismatch"):
        parse_archive_payload(_archive(model="v9999"))
    with pytest.raises(ValueError, match="archive date mismatch"):
        parse_archive_payload(_archive(date="2024-04-14"))


def test_missing_or_wrong_api_record_fails_closed() -> None:
    payload = json.loads(_api())
    payload["data"][0]["cve"] = "CVE-2024-0001"
    with pytest.raises(ValueError, match="exactly one"):
        parse_api_payload(payload)


def test_historical_epss_ablation_does_not_change_state_trajectory() -> None:
    result = run_epss_ablation(ROOT)
    assert result["state_trajectory_changed"] is False
    assert result["final_state_with_epss"] == "Report-Ready"
    assert result["final_state_without_epss"] == "Report-Ready"
    assert result["final_E_t_with_epss"] == result["final_E_t_without_epss"] == 1.0
    assert not any(row["state_changed"] for row in result["rows"])


def test_online_verification_report_removes_eligibility_blocker(tmp_path: Path) -> None:
    report = tmp_path / "online_report.json"
    report.write_text(json.dumps(verify_payloads(_api(), _archive()).to_dict(), indent=2))
    bundle = run_public_historical_replay(ROOT, epss_verification_report_path=report)["bundle"]
    assert bundle["historical_epss_verification"]["status"] == (
        "authoritative_dual_source_verified"
    )
    assert bundle["manuscript_eligibility"] is True
    assert bundle["evaluation_status"] == "PILOT_VERIFIED_NOT_FROZEN"
    assert bundle["eligibility_blockers"] == []
    assert bundle["historical_epss_verification"]["online_report_hash"]


def test_invalid_online_report_fails_closed(tmp_path: Path) -> None:
    report = tmp_path / "bad_report.json"
    payload = verify_payloads(_api(), _archive()).to_dict()
    payload["api_record"]["epss"] = "0.1"
    report.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="API_record|api_record|mismatch"):
        run_public_historical_replay(ROOT, epss_verification_report_path=report)


def test_online_cli_preserves_structured_mismatch_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sys

    from scripts import verify_historical_epss as verification_cli

    try:
        verify_payloads(_api(epss="0.95"), _archive())
    except HistoricalEpssVerificationError as exc:
        mismatch = exc
    else:  # pragma: no cover - the test setup must fail closed.
        raise AssertionError("mismatch fixture unexpectedly verified")

    def fail_online(_output_dir: Path) -> None:
        raise mismatch

    report = tmp_path / "diagnostic.json"
    monkeypatch.setattr(verification_cli, "verify_online", fail_online)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_historical_epss.py",
            "--online",
            "--output-dir",
            str(tmp_path / "raw"),
            "--report",
            str(report),
        ],
    )
    assert verification_cli.main() == 1
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["status"] == "verification_failed"
    assert payload["api_record"]["epss"] == "0.95"
    assert payload["archive_record"]["epss"] == "0.00371"
    assert payload["checks"]["api_archive_epss_agree"] is False
    assert "historical EPSS verification failed" in payload["error"]
