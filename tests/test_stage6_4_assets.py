import hashlib
import json
from pathlib import Path

from scripts.build_stage6_4_paper_assets import build

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/stage6_4_candidate"


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_stage6_4_paper_assets_are_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build(RESULTS, first)
    build(RESULTS, second)
    assert _tree_hashes(first) == _tree_hashes(second)
    manifest = json.loads((first / "data/stage6_4_asset_manifest.json").read_text())
    assert manifest["asset_status"] == "CANDIDATE_NOT_FROZEN"
    assert manifest["manuscript_eligible"] is False
