"""Authoritative historical EPSS verification for the CVE-2024-3400 replay.

The verifier compares three representations of the same historical record:

* the date-specific FIRST EPSS API response;
* the pinned official daily EPSS archive; and
* the repository's normalized verification record.

Online verification fails closed on missing records, metadata drift, or any
score/percentile disagreement. Raw online evidence is written before semantic
comparison so a failed gate remains diagnosable. Offline verification validates
the committed verification contract without pretending that it replaces the
online check.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import time
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import requests

TARGET_CVE = "CVE-2024-3400"
TARGET_DATE = "2024-04-15"
EXPECTED_EPSS = Decimal("0.00371")
EXPECTED_PERCENTILE = Decimal("0.72343")
EXPECTED_MODEL_VERSION = "v2023.03.01"
ARCHIVE_COMMIT = "ca26ecd7b9b806badabd6aedffdc8c4472ce6e85"
API_URL = (
    "https://api.first.org/data/v1/epss"
    f"?cve={TARGET_CVE}&date={TARGET_DATE}&envelope=true&pretty=true"
)
ARCHIVE_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/"
    f"{ARCHIVE_COMMIT}/2024/epss_scores-{TARGET_DATE}.csv.gz"
)


@dataclass(frozen=True)
class EpssRecord:
    cve: str
    date: str
    epss: str
    percentile: str
    model_version: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    status: str
    target_cve: str
    target_date: str
    expected_record: dict[str, str]
    api_record: dict[str, str] | None
    archive_record: dict[str, str] | None
    api_sha256: str | None
    archive_sha256: str | None
    extracted_row_sha256: str | None
    archive_commit: str
    api_url: str
    archive_url: str
    checks: dict[str, bool]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HistoricalEpssVerificationError(ValueError):
    """Fail-closed mismatch carrying the complete observed verification record."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        failed = sorted(key for key, passed in result.checks.items() if not passed)
        super().__init__(f"historical EPSS verification failed: {failed}")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decimal(value: Any, label: str) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc


def _canonical_decimal(value: Any, label: str) -> str:
    decimal = _decimal(value, label)
    normalized = format(decimal.normalize(), "f")
    return "0" if normalized in {"-0", ""} else normalized


def expected_record() -> EpssRecord:
    return EpssRecord(
        cve=TARGET_CVE,
        date=TARGET_DATE,
        epss=_canonical_decimal(EXPECTED_EPSS, "expected EPSS"),
        percentile=_canonical_decimal(EXPECTED_PERCENTILE, "expected percentile"),
        model_version=EXPECTED_MODEL_VERSION,
    )


def parse_api_payload(payload: bytes | str | dict[str, Any]) -> EpssRecord:
    if isinstance(payload, bytes):
        value = json.loads(payload.decode("utf-8"))
    elif isinstance(payload, str):
        value = json.loads(payload)
    else:
        value = payload
    if not isinstance(value, dict):
        raise ValueError("FIRST API response must be an object")
    if value.get("status") != "OK" or int(value.get("status-code", 0)) != 200:
        raise ValueError("FIRST API response does not report a successful status")
    rows = value.get("data")
    if not isinstance(rows, list):
        raise ValueError("FIRST API response data must be a list")
    matches = [row for row in rows if isinstance(row, dict) and row.get("cve") == TARGET_CVE]
    if len(matches) != 1:
        raise ValueError(f"FIRST API must contain exactly one {TARGET_CVE} record")
    row = matches[0]
    date = str(row.get("date") or "")
    if date != TARGET_DATE:
        raise ValueError(f"FIRST API date mismatch: expected {TARGET_DATE}, got {date!r}")
    return EpssRecord(
        cve=TARGET_CVE,
        date=date,
        epss=_canonical_decimal(row.get("epss"), "API EPSS"),
        percentile=_canonical_decimal(row.get("percentile"), "API percentile"),
    )


def _parse_metadata(line: str) -> dict[str, str]:
    if not line.startswith("#"):
        raise ValueError("EPSS archive is missing its metadata comment")
    metadata: dict[str, str] = {}
    for part in line[1:].strip().split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def parse_archive_payload(payload: bytes) -> tuple[EpssRecord, bytes]:
    try:
        decompressed = gzip.decompress(payload)
    except (OSError, EOFError) as exc:
        raise ValueError("EPSS archive is not a valid gzip file") from exc
    text = decompressed.decode("utf-8-sig")
    lines = text.splitlines()
    if len(lines) < 3:
        raise ValueError("EPSS archive is unexpectedly short")
    metadata = _parse_metadata(lines[0])
    model_version = metadata.get("model_version", "")
    if model_version != EXPECTED_MODEL_VERSION:
        raise ValueError(
            f"EPSS model mismatch: expected {EXPECTED_MODEL_VERSION}, got {model_version!r}"
        )
    score_date = metadata.get("score_date", "")
    if not score_date.startswith(TARGET_DATE):
        raise ValueError(f"EPSS archive date mismatch: expected {TARGET_DATE}, got {score_date!r}")
    reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
    matches = [row for row in reader if row.get("cve") == TARGET_CVE]
    if len(matches) != 1:
        raise ValueError(f"EPSS archive must contain exactly one {TARGET_CVE} record")
    row = matches[0]
    extracted = (
        f"cve,epss,percentile\n{TARGET_CVE},{row.get('epss', '')},{row.get('percentile', '')}\n"
    ).encode()
    record = EpssRecord(
        cve=TARGET_CVE,
        date=TARGET_DATE,
        epss=_canonical_decimal(row.get("epss"), "archive EPSS"),
        percentile=_canonical_decimal(row.get("percentile"), "archive percentile"),
        model_version=model_version,
    )
    return record, extracted


def _record_dict(record: EpssRecord | None) -> dict[str, str] | None:
    if record is None:
        return None
    return {key: value for key, value in asdict(record).items() if value is not None}


def verify_payloads(api_payload: bytes, archive_payload: bytes) -> VerificationResult:
    api = parse_api_payload(api_payload)
    archive, extracted = parse_archive_payload(archive_payload)
    expected = expected_record()
    checks = {
        "api_cve_matches": api.cve == expected.cve,
        "archive_cve_matches": archive.cve == expected.cve,
        "api_date_matches": api.date == expected.date,
        "archive_date_matches": archive.date == expected.date,
        "api_archive_epss_agree": _decimal(api.epss, "API EPSS")
        == _decimal(archive.epss, "archive EPSS"),
        "api_archive_percentile_agree": _decimal(api.percentile, "API percentile")
        == _decimal(archive.percentile, "archive percentile"),
        "normalized_epss_matches": _decimal(api.epss, "API EPSS")
        == _decimal(expected.epss, "normalized EPSS"),
        "normalized_percentile_matches": _decimal(api.percentile, "API percentile")
        == _decimal(expected.percentile, "normalized percentile"),
        "archive_model_matches": archive.model_version == expected.model_version,
    }
    status = "authoritative_dual_source_verified" if all(checks.values()) else "verification_failed"
    result = VerificationResult(
        status=status,
        target_cve=TARGET_CVE,
        target_date=TARGET_DATE,
        expected_record=_record_dict(expected) or {},
        api_record=_record_dict(api),
        archive_record=_record_dict(archive),
        api_sha256=_sha256_bytes(api_payload),
        archive_sha256=_sha256_bytes(archive_payload),
        extracted_row_sha256=_sha256_bytes(extracted),
        archive_commit=ARCHIVE_COMMIT,
        api_url=API_URL,
        archive_url=ARCHIVE_URL,
        checks=checks,
        limitations=[
            "The FIRST API does not expose the model-version field; model version is "
            "verified from the pinned daily archive metadata and FIRST's model schedule."
        ],
    )
    if status != "authoritative_dual_source_verified":
        raise HistoricalEpssVerificationError(result)
    return result


def verify_offline_contract(path: str | Path) -> VerificationResult:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = expected_record()
    record = value.get("expected_record") if isinstance(value, dict) else None
    if not isinstance(record, dict):
        raise ValueError("offline verification manifest requires expected_record")
    checks = {
        "cve_matches": str(record.get("cve")) == expected.cve,
        "date_matches": str(record.get("date")) == expected.date,
        "epss_matches": _decimal(record.get("epss"), "manifest EPSS")
        == _decimal(expected.epss, "expected EPSS"),
        "percentile_matches": _decimal(record.get("percentile"), "manifest percentile")
        == _decimal(expected.percentile, "expected percentile"),
        "model_matches": str(record.get("model_version")) == expected.model_version,
        "archive_commit_matches": str(value.get("archive_commit")) == ARCHIVE_COMMIT,
        "api_url_matches": str(value.get("api_url")) == API_URL,
        "archive_url_matches": str(value.get("archive_url")) == ARCHIVE_URL,
        "status_matches": str(value.get("status")) == "verification_contract_pending_online_gate",
        "fail_closed_enabled": value.get("fail_closed") is True,
    }
    if not all(checks.values()):
        failed = sorted(key for key, passed in checks.items() if not passed)
        raise ValueError(f"offline EPSS verification contract failed: {failed}")
    return VerificationResult(
        status="offline_contract_valid_online_verification_required",
        target_cve=TARGET_CVE,
        target_date=TARGET_DATE,
        expected_record=_record_dict(expected) or {},
        api_record=None,
        archive_record=None,
        api_sha256=None,
        archive_sha256=None,
        extracted_row_sha256=None,
        archive_commit=ARCHIVE_COMMIT,
        api_url=API_URL,
        archive_url=ARCHIVE_URL,
        checks=checks,
        limitations=[
            "Offline contract validation does not substitute for downloading and comparing "
            "the authoritative FIRST API and pinned archive records."
        ],
    )


def _download(url: str, *, attempts: int = 4, timeout: int = 45) -> bytes:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "sbom-to-audit-historical-epss-verifier/0.5.7"},
            )
            response.raise_for_status()
            if not response.content:
                raise ValueError(f"empty response from {url}")
            return response.content
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
    raise RuntimeError(f"failed to download {url}: {last_error}")


def verify_online(output_dir: str | Path) -> VerificationResult:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    api_payload = _download(API_URL)
    archive_payload = _download(ARCHIVE_URL)

    # Preserve raw evidence before comparison so a fail-closed mismatch is diagnosable.
    (destination / "cve_2024_3400_epss_2024-04-15_api.json").write_bytes(api_payload)
    (destination / "epss_scores-2024-04-15.csv.gz").write_bytes(archive_payload)
    try:
        _, extracted = parse_archive_payload(archive_payload)
    except ValueError:
        extracted = None
    if extracted is not None:
        (destination / "cve_2024_3400_epss_2024-04-15_row.csv").write_bytes(extracted)

    return verify_payloads(api_payload, archive_payload)
