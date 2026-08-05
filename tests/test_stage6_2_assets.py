import csv
import json
from pathlib import Path
from xml.etree import ElementTree

from scripts.build_stage6_2_paper_assets import build
from scripts.run_stage6_2_robustness import run


def test_stage6_2_paper_assets_are_machine_generated_and_registered(tmp_path: Path) -> None:
    results = tmp_path / "results"
    assets = tmp_path / "assets"
    run(results)
    generated = build(results, assets)

    ElementTree.parse(generated["threshold_figure"])
    ElementTree.parse(generated["factor_figure"])
    manifest = json.loads(generated["manifest"].read_text(encoding="utf-8"))
    assert manifest["asset_status"] == "CANDIDATE_NOT_FROZEN"
    assert manifest["manuscript_eligible"] is False
    assert len(manifest["generated_asset_hashes"]) == 7

    with generated["threshold_table"].open(encoding="utf-8", newline="") as handle:
        threshold_rows = list(csv.DictReader(handle))
    assert len(threshold_rows) == 35

    with generated["negative_table"].open(encoding="utf-8", newline="") as handle:
        negative_rows = list(csv.DictReader(handle))
    assert len(negative_rows) == 8
    assert all(row["rejected_as_expected"] == "True" for row in negative_rows)
