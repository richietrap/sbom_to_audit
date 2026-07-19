#!/usr/bin/env python3
"""Generate Stage 3 pilot comparison assets from replay outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any

SCENARIOS = ("ghost_logger", "false_comfort", "false_comfort_control")


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


def _comparison_svg(path: Path, main: dict[str, Any], control: dict[str, Any]) -> None:
    width, height = 900, 360
    cards = [
        ("False Comfort", main, 70),
        ("Scope-matched control", control, 480),
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="45" y="40" font-family="sans-serif" font-size="22" font-weight="bold">Supplier-assurance scope comparison</text>',
        '<text x="850" y="40" text-anchor="end" font-family="sans-serif" font-size="12">PILOT — not final paper evidence</text>',
    ]
    for title, payload, x in cards:
        parts.append(
            f'<rect x="{x}" y="75" width="350" height="225" rx="10" fill="#f4f4f4" stroke="#222"/>'
        )
        parts.append(
            f'<text x="{x + 175}" y="108" text-anchor="middle" font-family="sans-serif" font-size="18" font-weight="bold">{html.escape(title)}</text>'
        )
        rows = [
            ("Assertion variant", payload["assertion_variant"]),
            ("Target variant", payload["target_variant"]),
            ("Scope applicability", payload["scope_applicability"]),
            ("Initial A_t", f"{payload['initial_A_t']:.2f}"),
            ("Initial state", payload["initial_state"]),
            ("Final state", payload["final_state"]),
        ]
        for index, (label, value) in enumerate(rows):
            y = 140 + index * 27
            parts.append(
                f'<text x="{x + 20}" y="{y}" font-family="sans-serif" font-size="13" font-weight="bold">{html.escape(label)}:</text>'
            )
            parts.append(
                f'<text x="{x + 170}" y="{y}" font-family="sans-serif" font-size="13">{html.escape(str(value))}</text>'
            )
    parts.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    scenario_rows: list[dict[str, Any]] = []
    packs: dict[str, dict[str, Any]] = {}
    state_rows: dict[str, list[dict[str, str]]] = {}
    metrics: dict[str, dict[str, Any]] = {}
    for scenario_id in SCENARIOS:
        packs[scenario_id] = json.loads(
            (output_root / "evidence_packs" / f"{scenario_id}.json").read_text(encoding="utf-8")
        )
        state_rows[scenario_id] = _read_csv(output_root / "state_logs" / f"{scenario_id}.csv")
        metrics[scenario_id] = json.loads(
            (output_root / "metrics" / f"{scenario_id}_metrics.json").read_text(encoding="utf-8")
        )
        pack = packs[scenario_id]
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "event_count": len(state_rows[scenario_id]),
                "source_count": metrics[scenario_id]["supplemental"]["source_count"],
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

    summary_path = destination / "tables" / "stage3_scenario_summary.csv"
    summary_fields = list(scenario_rows[0])
    _write_csv(summary_path, scenario_rows, summary_fields)

    fc_event_path = destination / "tables" / "false_comfort_event_replay.csv"
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
    _write_csv(
        fc_event_path,
        [{key: row[key] for key in event_fields} for row in state_rows["false_comfort"]],
        event_fields,
    )

    scope_rows: list[dict[str, Any]] = []
    payloads: dict[str, dict[str, Any]] = {}
    for scenario_id in ("false_comfort", "false_comfort_control"):
        supplier = packs[scenario_id]["supplier_assertions"]
        payload = {
            "scenario_id": scenario_id,
            "asserted_status": supplier["asserted_csaf_vex_status"],
            "effective_status": supplier["csaf_vex_status"],
            "assertion_variant": supplier["assertion_scope"].get("product_variant", "broad"),
            "target_variant": supplier["target_scope"].get("product_variant", "unspecified"),
            "scope_applicability": supplier["scope_applicability"],
            "initial_A_t": float(state_rows[scenario_id][0]["A_t"]),
            "initial_state": state_rows[scenario_id][0]["observed_state"],
            "final_state": packs[scenario_id]["decision_state"]["recommended_state"],
        }
        payloads[scenario_id] = payload
        scope_rows.append(payload)
    scope_path = destination / "tables" / "false_comfort_scope_applicability.csv"
    _write_csv(scope_path, scope_rows, list(scope_rows[0]))

    figure_path = destination / "figures" / "false_comfort_scope_comparison.svg"
    _comparison_svg(figure_path, payloads["false_comfort"], payloads["false_comfort_control"])

    generated = (summary_path, fc_event_path, scope_path, figure_path)
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
        ],
        "generation_script": "paper_assets/scripts/build_stage3_assets.py",
        "generation_script_hash": _sha256(script_path),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in source_paths
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
    }
    metadata_path = destination / "data" / "stage3_asset_manifest.json"
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
