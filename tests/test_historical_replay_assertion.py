"""Tests for the verified historical-replay eligibility assertion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.assert_verified_historical_replay import validate_bundle


def _write_bundle(
    path: Path,
    *,
    eligible: bool = True,
    status: str = "authoritative_dual_source_verified",
    digest: str = "a" * 64,
) -> None:
    payload = {
        "manuscript_eligibility": eligible,
        "historical_epss_verification": {
            "status": status,
            "online_report_hash": digest,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_verified_bundle_passes(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    _write_bundle(path)
    value = validate_bundle(path)
    assert value["manuscript_eligibility"] is True


@pytest.mark.parametrize(
    ("eligible", "status", "digest"),
    [
        (False, "authoritative_dual_source_verified", "a" * 64),
        (True, "verification_contract_valid_online_gate_required", "a" * 64),
        (True, "authoritative_dual_source_verified", "short"),
    ],
)
def test_unverified_bundle_fails_closed(
    tmp_path: Path, eligible: bool, status: str, digest: str
) -> None:
    path = tmp_path / "bundle.json"
    _write_bundle(path, eligible=eligible, status=status, digest=digest)
    with pytest.raises(ValueError):
        validate_bundle(path)
