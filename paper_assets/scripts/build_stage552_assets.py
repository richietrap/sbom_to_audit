#!/usr/bin/env python3
"""Generate Stage 5.5.2 corrected historical EPSS verification and ablation assets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build(output_root: Path, destination: Path) -> dict[str, str]:
    contract_path = Path(
        "data/historical_replays/cve_2024_3400/epss/verification_manifest.json"
    ).resolve()
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    public_bundle_path = output_root / "historical_public/cve_2024_3400_public_bundle.json"
    public_bundle = json.loads(public_bundle_path.read_text(encoding="utf-8"))
    eligible = bool(public_bundle["manuscript_eligibility"])
    record = contract["expected_record"]
    ablation_json = output_root / "historical_public/cve_2024_3400_epss_ablation.json"
    ablation_csv = output_root / "historical_public/cve_2024_3400_epss_ablation.csv"
    ablation = json.loads(ablation_json.read_text(encoding="utf-8"))

    verification_table = destination / "tables/cve_2024_3400_epss_verification.csv"
    _write_csv(
        verification_table,
        [
            {
                "cve": record["cve"],
                "score_date": record["date"],
                "epss": record["epss"],
                "percentile": record["percentile"],
                "model_version": record["model_version"],
                "verification_status": contract["status"],
                "archive_commit": contract["archive_commit"],
                "acceptance_gate": contract["acceptance_rule"],
            }
        ],
        [
            "cve",
            "score_date",
            "epss",
            "percentile",
            "model_version",
            "verification_status",
            "archive_commit",
            "acceptance_gate",
        ],
    )

    ablation_table = destination / "tables/cve_2024_3400_epss_ablation.csv"
    ablation_table.parent.mkdir(parents=True, exist_ok=True)
    ablation_table.write_bytes(ablation_csv.read_bytes())

    figure = destination / "figures/cve_2024_3400_epss_verification.svg"
    figure.parent.mkdir(parents=True, exist_ok=True)
    figure.write_text(
        "\n".join(
            [
                '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="420" viewBox="0 0 1100 420">',
                '<rect width="100%" height="100%" fill="white"/>',
                '<text x="550" y="38" text-anchor="middle" font-family="sans-serif" font-size="23" font-weight="bold">CVE-2024-3400 historical EPSS verification</text>',
                '<rect x="70" y="110" width="250" height="105" fill="white" stroke="#222"/>',
                '<text x="195" y="145" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">FIRST date-specific API</text>',
                '<text x="195" y="175" text-anchor="middle" font-family="sans-serif" font-size="13">score + percentile + date</text>',
                '<rect x="425" y="110" width="250" height="105" fill="white" stroke="#222"/>',
                '<text x="550" y="145" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">Pinned daily archive</text>',
                '<text x="550" y="175" text-anchor="middle" font-family="sans-serif" font-size="13">score + percentile + model</text>',
                '<rect x="780" y="110" width="250" height="105" fill="white" stroke="#222"/>',
                '<text x="905" y="145" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">Normalized replay record</text>',
                f'<text x="905" y="175" text-anchor="middle" font-family="sans-serif" font-size="13">EPSS {record["epss"]}; percentile {record["percentile"]}</text>',
                '<line x1="320" y1="162" x2="425" y2="162" stroke="#222" stroke-width="2"/>',
                '<line x1="675" y1="162" x2="780" y2="162" stroke="#222" stroke-width="2"/>',
                '<text x="550" y="275" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">Fail closed unless all values agree</text>',
                f'<text x="550" y="315" text-anchor="middle" font-family="sans-serif" font-size="14">Ablation changes state trajectory: {str(ablation["state_trajectory_changed"]).lower()}</text>',
                '<text x="550" y="350" text-anchor="middle" font-family="sans-serif" font-size="12">Raw API and gzip evidence are preserved in the online Colab checkpoint bundle.</text>',
                "</svg>",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    generated = (verification_table, ablation_table, figure)
    metadata = {
        "asset_status": (
            "PILOT_VERIFIED_NOT_FROZEN" if eligible else "PILOT_VERIFICATION_CANDIDATE"
        ),
        "manuscript_eligible": eligible,
        "source_run_ids": [
            "HIST-CVE-2024-3400-PUBLIC-STAGE552-CORRECTED-CANDIDATE-001",
            "HIST-CVE-2024-3400-REF-STAGE552-CORRECTED-CANDIDATE-001",
        ],
        "generation_script": "paper_assets/scripts/build_stage552_assets.py",
        "generation_script_hash": _sha256(Path(__file__).resolve()),
        "source_data_hashes": {
            "verification_manifest.json": _sha256(contract_path),
            "cve_2024_3400_public_bundle.json": _sha256(public_bundle_path),
            "cve_2024_3400_epss_ablation.json": _sha256(ablation_json),
            "cve_2024_3400_epss_ablation.csv": _sha256(ablation_csv),
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
        "eligibility_note": (
            "Eligible for later evaluation freezing after the corrected authoritative online report is supplied."
            if eligible
            else "Corrected candidate only until required GitHub and Colab online verification gates pass."
        ),
    }
    manifest = destination / "data/stage552_asset_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        path.relative_to(destination).as_posix(): _sha256(path) for path in (*generated, manifest)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output_root.resolve(), args.destination.resolve()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
