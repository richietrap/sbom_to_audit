from pathlib import Path

from scripts.build_stage6_3_paper_assets import build

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "stage6_3_candidate"


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_stage6_3_candidate_assets_are_registered() -> None:
    assert (ROOT / "paper_assets/figures/stage6_3_mutation_detection.svg").is_file()
    assert (ROOT / "paper_assets/tables/stage6_3_family_summary.csv").is_file()
    assert (ROOT / "paper_assets/tables/stage6_3_baseline_survivors.csv").is_file()
    assert (ROOT / "paper_assets/data/stage6_3_asset_manifest.json").is_file()


def test_stage6_3_asset_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build(RESULTS, first)
    build(RESULTS, second)
    assert _tree_bytes(first) == _tree_bytes(second)
