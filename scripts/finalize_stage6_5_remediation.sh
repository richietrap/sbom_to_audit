#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python scripts/validate_stage6_5_remediation.py
python scripts/run_stage6_5_performance_remediation.py \
  --profile full \
  --destination evaluation/stage6_5_candidate/performance_remediation
python scripts/validate_stage6_5_performance_remediation.py \
  --results evaluation/stage6_5_candidate/performance_remediation
python scripts/build_stage6_5_paper_assets.py \
  --results evaluation/stage6_5_candidate/performance_remediation \
  --destination paper_assets

python - <<'PY'
import csv
import json
from pathlib import Path

from sbom_to_audit.utils.hashing import sha256_file

ROOT = Path.cwd()
RUN_ID = "STAGE6-5-PERFORMANCE-REMEDIATION-CANDIDATE-001"
ASSET_IDS = {"F13", "T32", "T33"}


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV header is missing: {path}")
        return list(reader.fieldnames), list(reader)


def write_rows(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


report_path = ROOT / "evaluation/stage6_5_candidate/performance_remediation/stage6_5_performance_report.json"
report = json.loads(report_path.read_text(encoding="utf-8"))
environment_path = ROOT / "evaluation/environments/stage6_5_local_build.json"
environment = {
    "environment_id": "stage6-5-local-build",
    "stage": "6.5",
    "package_version": "0.6.5",
    "run_id": RUN_ID,
    "source_commit_observed_before_candidate_commit": report.get("source_commit"),
    "source_tree_dirty_during_candidate_measurement": report.get("source_tree_dirty"),
    "benchmark_environment": report.get("environment"),
    "measurement_profile": report.get("profile"),
    "warmup_runs": report.get("warmup_runs"),
    "measured_runs": report.get("measured_runs"),
    "memory_observation_count": report.get("memory_observation_count"),
    "memory_observation_granularity": report.get("memory_observation_granularity"),
    "interpretation": (
        "Local Stage 6.5 remediation candidate. New performance values supersede Stage 6.4 "
        "only for the remediation run and remain manuscript-ineligible pending targeted "
        "independent re-audit and final evaluation freeze."
    ),
}
environment_path.write_text(
    json.dumps(environment, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)

run_registry = ROOT / "evaluation/run_registry.csv"
run_fields, run_rows = read_rows(run_registry)
matching_runs = [row for row in run_rows if row.get("run_id") == RUN_ID]
if len(matching_runs) > 1:
    raise ValueError(f"expected at most one {RUN_ID} row, found {len(matching_runs)}")
run_row = matching_runs[0] if matching_runs else {field: "" for field in run_fields}
run_row.update(
    {
        "run_id": RUN_ID,
        "git_commit": str(report.get("source_commit") or "not_recorded_stage65_candidate_build"),
        "scenario_id": "matched_controlled_scenario_suite",
        "scenario_version": "stage6.5-performance-remediation-v0.2",
        "run_type": "PERFORMANCE_AND_SCALE_REMEDIATION",
        "evaluation_status": "CANDIDATE_NOT_FROZEN",
        "environment_id": "stage6-5-local-build",
        "input_manifest_hash": sha256_file(
            ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml"
        ),
        "output_manifest_hash": sha256_file(
            ROOT
            / "evaluation/stage6_5_candidate/performance_remediation/stage6_5_output_manifest.json"
        ),
        "started_at": "not_recorded_candidate_execution",
        "completed_at": "not_recorded_candidate_execution",
        "status": "PASS",
        "notes": (
            "Stage 6.5 remediation rerun with one preserved raw worker high-water RSS "
            "observation per workload; environment-specific candidate only."
        ),
    }
)
if not matching_runs:
    run_rows.append(run_row)
write_rows(run_registry, run_fields, run_rows)

asset_register = ROOT / "paper_assets/figure_table_register.csv"
asset_fields, asset_rows = read_rows(asset_register)
protocol_hash = sha256_file(ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml")
builder_hash = sha256_file(ROOT / "scripts/build_stage6_5_paper_assets.py")
asset_specs = {
    "F13": {
        "provisional_title": "Stage 6.5 remediated observed latency scaling",
        "asset_type": "figure",
        "paper_section": "Evaluation and Results: Performance and Scale",
        "source_data": "evaluation/stage6_5_candidate/performance_remediation/stage6_5_scale_summary.csv",
        "output_path": "paper_assets/figures/stage6_5_latency_scaling.svg",
    },
    "T32": {
        "provisional_title": "Stage 6.5 remediated axis endpoint performance summary",
        "asset_type": "table",
        "paper_section": "Evaluation and Results: Performance and Scale",
        "source_data": "evaluation/stage6_5_candidate/performance_remediation/stage6_5_scale_summary.csv",
        "output_path": "paper_assets/tables/stage6_5_axis_endpoints.csv",
    },
    "T33": {
        "provisional_title": "Stage 6.5 remediated detailed scale summary",
        "asset_type": "table",
        "paper_section": "Evaluation and Results: Performance and Scale",
        "source_data": "evaluation/stage6_5_candidate/performance_remediation/stage6_5_scale_summary.csv",
        "output_path": "paper_assets/tables/stage6_5_scale_summary.csv",
    },
}
for asset_id, spec in asset_specs.items():
    matches = [row for row in asset_rows if row.get("asset_id") == asset_id]
    if len(matches) > 1:
        raise ValueError(f"duplicate Stage 6.5 asset ID: {asset_id}")
    row = matches[0] if matches else {field: "" for field in asset_fields}
    row.update(
        {
            "asset_id": asset_id,
            "provisional_title": spec["provisional_title"],
            "asset_type": spec["asset_type"],
            "paper_section": spec["paper_section"],
            "source_run_ids": RUN_ID,
            "source_data": spec["source_data"],
            "input_manifest_hash": protocol_hash,
            "generation_script": "scripts/build_stage6_5_paper_assets.py",
            "generation_script_hash": builder_hash,
            "output_path": spec["output_path"],
            "output_hash": sha256_file(ROOT / spec["output_path"]),
            "status": "CANDIDATE_NOT_FROZEN",
            "verified_date": "2026-08-12",
            "manuscript_status": "NOT_ELIGIBLE_UNTIL_TARGETED_REAUDIT_AND_FREEZE",
        }
    )
    if not matches:
        asset_rows.append(row)
write_rows(asset_register, asset_fields, asset_rows)

closure_path = ROOT / "evaluation/stage6_5_candidate/finding_closure.csv"
closure_fields, closure_rows = read_rows(closure_path)
for row in closure_rows:
    if row["finding_id"] == "S65-F001":
        row["closure_evidence_hash"] = sha256_file(ROOT / "src/sbom_to_audit/model/metrics.py")
        row["verification_result"] = "LOCAL_CONFORMANCE_PASS_AWAITING_INDEPENDENT_REAUDIT"
    elif row["finding_id"] == "S65-F004":
        row["closure_evidence_hash"] = sha256_file(
            ROOT / "evaluation/stage6_5_candidate/performance_remediation/stage6_5_output_manifest.json"
        )
        row["verification_result"] = "LOCAL_RAW_RSS_RECOMPUTATION_PASS_AWAITING_INDEPENDENT_REAUDIT"
write_rows(closure_path, closure_fields, closure_rows)

manifest_path = ROOT / "MANIFEST.md"
text = manifest_path.read_text(encoding="utf-8")
parts = text.split("## v0.2.1", 1)
prefix = parts[0]
suffix = "## v0.2.1" + parts[1] if len(parts) == 2 else ""
import re
existing = {}
for path, purpose, status in re.findall(
    r"^\| `([^`]+)` \| ([^|]+?) \| ([^|]+?) \|$",
    prefix,
    flags=re.MULTILINE,
):
    existing[path] = (purpose.strip(), status.strip())
ignored = {
    ".git", ".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".venv", ".qa-venv", ".quality-venv", "__pycache__", "build", "dist"
}
generated_output_dirs = {
    Path("outputs/evidence_packs"),
    Path("outputs/state_logs"),
    Path("outputs/conflict_reports"),
    Path("outputs/metrics"),
    Path("outputs/source_manifests"),
    Path("outputs/audit_ledgers"),
    Path("outputs/validation"),
    Path("outputs/stage6_baseline"),
    Path("outputs/stage6_1_manual_baseline"),
    Path("outputs/stage6_1_comparison"),
    Path("outputs/stage6_1_validation"),
}
actual = []
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    relative = path.relative_to(ROOT)
    if any(part in ignored or part.endswith(".egg-info") for part in relative.parts):
        continue
    if path.suffix == ".pyc" or relative.name.startswith(".coverage"):
        continue
    if (
        any(relative.is_relative_to(directory) for directory in generated_output_dirs)
        and relative.name != ".gitkeep"
    ):
        continue
    actual.append(relative.as_posix())
actual = sorted(set(actual))

def purpose_for(relative: str) -> str:
    if relative.startswith("evaluation/stage6_5_candidate/"):
        return "Stage 6.5 remediation candidate evidence or finding-closure record."
    if relative.startswith("evaluation/environments/stage6_5"):
        return "Stage 6.5 environment metadata for the local remediation run."
    if relative.startswith("paper_assets/") and "stage6_5" in relative:
        return "Stage 6.5 candidate figure, table, or asset provenance manifest."
    return "Stage 6.5 remediation source, protocol, validation, test, or governance artefact."

rows = []
for relative in actual:
    purpose, status = existing.get(
        relative,
        (purpose_for(relative), "Added or generated v0.6.5"),
    )
    rows.append(f"| `{relative}` | {purpose} | {status} |")
header = prefix.split("| Path | Purpose | Status |", 1)[0]
header = re.sub(
    r"\*\*Implementation baseline:\*\* .*",
    "**Implementation baseline:** Stage 6.5 independent-audit remediation candidate, package v0.6.5",
    header,
)
header = re.sub(r"\*\*Expected files:\*\* \d+", f"**Expected files:** {len(actual)}", header)
header = re.sub(r"\*\*Created files:\*\* \d+", f"**Created files:** {len(actual)}", header)
header = re.sub(r"\*\*Missing files:\*\* \d+", "**Missing files:** 0", header)
table = "| Path | Purpose | Status |\n|---|---|---|\n" + "\n".join(rows) + "\n\n"
manifest_path.write_text(header + table + suffix, encoding="utf-8", newline="\n")
PY

python scripts/validate_stage6_5_remediation.py
python scripts/validate_stage6_5_performance_remediation.py \
  --results evaluation/stage6_5_candidate/performance_remediation

echo "PASS: Stage 6.5 AR and raw-RSS remediation candidate finalized locally"
