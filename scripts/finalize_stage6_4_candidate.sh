#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python scripts/run_stage6_4_performance.py \
  --profile full \
  --destination evaluation/stage6_4_candidate
python scripts/validate_stage6_4_evaluation.py \
  --results evaluation/stage6_4_candidate
python scripts/build_stage6_4_paper_assets.py \
  --results evaluation/stage6_4_candidate \
  --destination paper_assets

python - <<'PY'
import csv
import json
from pathlib import Path

from sbom_to_audit.utils.hashing import sha256_file

ROOT = Path.cwd()
RUN_ID = "STAGE6-4-PERFORMANCE-CANDIDATE-001"
ASSET_IDS = {"F12", "T30", "T31"}


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


report_path = ROOT / "evaluation/stage6_4_candidate/stage6_4_performance_report.json"
report = json.loads(report_path.read_text(encoding="utf-8"))
environment_path = ROOT / "evaluation/environments/stage6_4_local_build.json"
environment = {
    "environment_id": "stage6-4-local-build",
    "stage": "6.4",
    "package_version": "0.6.4",
    "run_id": RUN_ID,
    "source_commit_observed_before_candidate_commit": report.get("source_commit"),
    "source_tree_dirty_during_candidate_measurement": report.get("source_tree_dirty"),
    "benchmark_environment": report.get("environment"),
    "measurement_profile": report.get("profile"),
    "warmup_runs": report.get("warmup_runs"),
    "measured_runs": report.get("measured_runs"),
    "interpretation": (
        "Local development candidate only. Exact-commit Colab performance evidence is retained "
        "separately before any final manuscript freeze."
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
if len(matching_runs) != 1:
    raise ValueError(f"expected one {RUN_ID} row, found {len(matching_runs)}")
matching_runs[0]["input_manifest_hash"] = sha256_file(
    ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml"
)
matching_runs[0]["output_manifest_hash"] = sha256_file(
    ROOT / "evaluation/stage6_4_candidate/stage6_4_output_manifest.json"
)
write_rows(run_registry, run_fields, run_rows)

asset_register = ROOT / "paper_assets/figure_table_register.csv"
asset_fields, asset_rows = read_rows(asset_register)
selected_assets = [row for row in asset_rows if row.get("asset_id") in ASSET_IDS]
if {row["asset_id"] for row in selected_assets} != ASSET_IDS:
    raise ValueError("Stage 6.4 figure/table register is incomplete")
protocol_hash = sha256_file(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
builder_hash = sha256_file(ROOT / "scripts/build_stage6_4_paper_assets.py")
for row in selected_assets:
    row["input_manifest_hash"] = protocol_hash
    row["generation_script_hash"] = builder_hash
    row["output_hash"] = sha256_file(ROOT / row["output_path"])
write_rows(asset_register, asset_fields, asset_rows)
PY

echo "PASS: Stage 6.4 observed candidate evidence, assets, environment, and hashes refreshed"
