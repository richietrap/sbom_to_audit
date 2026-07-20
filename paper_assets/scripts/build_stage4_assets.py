#!/usr/bin/env python3
"""Generate Stage 4 pilot assets for Operational Outlier and its control."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any

SCENARIOS = (
    "ghost_logger",
    "false_comfort",
    "false_comfort_control",
    "operational_outlier",
    "operational_outlier_control",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _impact_svg(path: Path, main: dict[str, Any], control: dict[str, Any]) -> None:
    width, height = 980, 410
    cards = [
        ("Operational Outlier", main, 55),
        ("Counterfactual lower-impact control", control, 520),
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="45" y="40" font-family="sans-serif" font-size="22" font-weight="bold">Matched technical evidence, different operational impact</text>',
        '<text x="935" y="40" text-anchor="end" font-family="sans-serif" font-size="12">PILOT — not final paper evidence</text>',
    ]
    for title, payload, x in cards:
        parts.append(
            f'<rect x="{x}" y="75" width="405" height="270" rx="10" fill="#f5f5f5" stroke="#222"/>'
        )
        parts.append(
            f'<text x="{x + 202}" y="108" text-anchor="middle" font-family="sans-serif" font-size="18" font-weight="bold">{html.escape(title)}</text>'
        )
        rows = [
            ("CVSS base", f"{payload['cvss_base_score']:.1f} {payload['cvss_base_severity']}"),
            (
                "KEV / EPSS percentile",
                f"{payload['kev_status']} / {payload['epss_percentile']:.2f}",
            ),
            ("Reachability A_t", f"{payload['A_t']:.2f}"),
            ("Asset context", f"{payload['asset_criticality']} / {payload['deployment_scope']}"),
            ("Operational impact I_t", f"{payload['I_t']:.2f}"),
            ("State after reachability", payload["state_after_reachability"]),
            ("Final state", payload["final_state"]),
        ]
        for index, (label, value) in enumerate(rows):
            y = 143 + index * 29
            parts.append(
                f'<text x="{x + 18}" y="{y}" font-family="sans-serif" font-size="13" font-weight="bold">{html.escape(label)}:</text>'
            )
            parts.append(
                f'<text x="{x + 205}" y="{y}" font-family="sans-serif" font-size="13">{html.escape(str(value))}</text>'
            )
    parts.append(
        '<text x="490" y="382" text-anchor="middle" font-family="sans-serif" font-size="13">The pair reuses identical non-asset source bytes and workflow timing; only the two I_t inputs differ.</text>'
    )
    parts.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    packs: dict[str, dict[str, Any]] = {}
    states: dict[str, list[dict[str, str]]] = {}
    metrics: dict[str, dict[str, Any]] = {}
    scenario_rows: list[dict[str, Any]] = []

    for scenario_id in SCENARIOS:
        packs[scenario_id] = json.loads(
            (output_root / "evidence_packs" / f"{scenario_id}.json").read_text(encoding="utf-8")
        )
        states[scenario_id] = _read_csv(output_root / "state_logs" / f"{scenario_id}.csv")
        metrics[scenario_id] = json.loads(
            (output_root / "metrics" / f"{scenario_id}_metrics.json").read_text(encoding="utf-8")
        )
        pack = packs[scenario_id]
        vulnerability = pack["vulnerability_intelligence"]
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "event_count": len(states[scenario_id]),
                "source_count": metrics[scenario_id]["supplemental"]["source_count"],
                "cvss_base_score": vulnerability.get("cvss_base_score", ""),
                "final_state": pack["decision_state"]["recommended_state"],
                "authorized_state": pack["decision_state"]["authorized_state"] or "",
                "E_t": pack["orchestration_metrics"]["E_t"],
                "A_t": pack["orchestration_metrics"]["A_t"],
                "I_t": pack["orchestration_metrics"]["I_t"],
                "C_t": pack["orchestration_metrics"]["C_t"],
                "SC": metrics[scenario_id]["SC"],
                "TR": metrics[scenario_id]["TR"],
            }
        )

    summary_path = destination / "tables" / "stage4_scenario_summary.csv"
    _write_csv(summary_path, scenario_rows, list(scenario_rows[0]))

    event_fields = [
        "event_id",
        "delta_t_hours",
        "E_t",
        "A_t",
        "I_t",
        "M_t",
        "U_t",
        "C_t",
        "observed_state",
        "authorized_state",
        "deadline_posture",
        "state_match",
    ]
    event_path = destination / "tables" / "operational_outlier_event_replay.csv"
    _write_csv(
        event_path,
        [{key: row[key] for key in event_fields} for row in states["operational_outlier"]],
        event_fields,
    )

    comparison_rows: list[dict[str, Any]] = []
    figure_payloads: dict[str, dict[str, Any]] = {}
    for scenario_id in ("operational_outlier", "operational_outlier_control"):
        pack = packs[scenario_id]
        vulnerability = pack["vulnerability_intelligence"]
        asset = pack["asset_context"]
        reachability_row = states[scenario_id][1]
        payload = {
            "scenario_id": scenario_id,
            "cvss_base_score": float(vulnerability["cvss_base_score"]),
            "cvss_base_severity": vulnerability["cvss_base_severity"],
            "kev_status": vulnerability["cisa_kev_status"],
            "epss_percentile": float(vulnerability["epss_percentile"]),
            "E_t": float(reachability_row["E_t"]),
            "A_t": float(reachability_row["A_t"]),
            "asset_criticality": asset["asset_criticality"],
            "deployment_scope": asset["deployment_scope"],
            "I_t": float(reachability_row["I_t"]),
            "state_after_reachability": reachability_row["observed_state"],
            "final_state": pack["decision_state"]["recommended_state"],
        }
        comparison_rows.append(payload)
        figure_payloads[scenario_id] = payload

    comparison_path = destination / "tables" / "operational_impact_comparison.csv"
    _write_csv(comparison_path, comparison_rows, list(comparison_rows[0]))

    figure_path = destination / "figures" / "operational_outlier_impact_comparison.svg"
    _impact_svg(
        figure_path,
        figure_payloads["operational_outlier"],
        figure_payloads["operational_outlier_control"],
    )

    generated = (summary_path, event_path, comparison_path, figure_path)
    source_paths = tuple(
        path
        for scenario_id in SCENARIOS
        for path in (
            output_root / "evidence_packs" / f"{scenario_id}.json",
            output_root / "state_logs" / f"{scenario_id}.csv",
            output_root / "metrics" / f"{scenario_id}_metrics.json",
        )
    )
    script_path = Path(__file__).resolve()
    metadata = {
        "asset_status": "PILOT",
        "manuscript_eligible": False,
        "source_run_ids": [
            "GL-STAGE2-0-1-PILOT-001",
            "FC-STAGE3-PILOT-001",
            "FCC-STAGE3-PILOT-001",
            "OO-STAGE4-PILOT-001",
            "OOC-STAGE4-PILOT-001",
        ],
        "generation_script": "paper_assets/scripts/build_stage4_assets.py",
        "generation_script_hash": _sha256(script_path),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in source_paths
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
    }
    metadata_path = destination / "data" / "stage4_asset_manifest.json"
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {"metadata": str(metadata_path), **{path.stem: str(path) for path in generated}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output_root.resolve(), args.destination.resolve()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
