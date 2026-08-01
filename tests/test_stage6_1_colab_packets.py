import ast
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "stage6_1_5_colab_checkpoint.ipynb"
EXPORTER = ROOT / "scripts" / "export_stage6_1_baseline_packets.py"


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, list):
        return "".join(str(line) for line in source)
    return str(source)


def _load_module(path: Path, source: str) -> ModuleType:
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _packet_validator(tmp_path: Path) -> Callable[[Path], list[dict[str, object]]]:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    source = _cell_source(notebook["cells"][5])
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "validate_packet_export"
    )
    module_source = (
        "import hashlib\nimport json\nfrom pathlib import Path\n\n" + ast.unparse(function) + "\n"
    )
    module = _load_module(tmp_path / "notebook_packet_validator.py", module_source)
    return module.validate_packet_export


@pytest.fixture(scope="module")
def pristine_packet_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("stage615-packets") / "export"
    completed = subprocess.run(
        [sys.executable, str(EXPORTER), "--destination", str(destination)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return destination


@pytest.fixture
def packet_root(pristine_packet_root: Path, tmp_path: Path) -> Path:
    destination = tmp_path / "packets"
    shutil.copytree(pristine_packet_root, destination)
    return destination


def _registry(packet_root: Path) -> dict[str, Any]:
    path = packet_root / "packet_registry.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _write_registry(packet_root: Path, payload: dict[str, Any]) -> None:
    (packet_root / "packet_registry.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def test_stage6_1_5_packet_validator_accepts_export(packet_root: Path, tmp_path: Path) -> None:
    packets = _packet_validator(tmp_path)(packet_root)
    assert len(packets) == 28


def test_stage6_1_5_packet_validator_rejects_manifest_tampering(
    packet_root: Path,
    tmp_path: Path,
) -> None:
    row = _registry(packet_root)["packets"][0]
    manifest = packet_root / row["manifest_path"]
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="manifest hash mismatch"):
        _packet_validator(tmp_path)(packet_root)


def test_stage6_1_5_packet_validator_rejects_artifact_tampering(
    packet_root: Path,
    tmp_path: Path,
) -> None:
    row = _registry(packet_root)["packets"][0]
    manifest_path = packet_root / row["manifest_path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = manifest["released_artifacts"][0]
    artifact_path = manifest_path.parent / artifact["filename"]
    artifact_path.write_bytes(artifact_path.read_bytes() + b"tamper")

    with pytest.raises(RuntimeError, match="artifact hash mismatch"):
        _packet_validator(tmp_path)(packet_root)


def test_stage6_1_5_packet_validator_rejects_forbidden_oracle_key(
    packet_root: Path,
    tmp_path: Path,
) -> None:
    registry = _registry(packet_root)
    row = registry["packets"][0]
    manifest_path = packet_root / row["manifest_path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["expected_state"] = "Escalate"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    row["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    _write_registry(packet_root, registry)

    with pytest.raises(RuntimeError, match="Blinding boundary violation"):
        _packet_validator(tmp_path)(packet_root)


def test_stage6_1_5_packet_validator_rejects_unsafe_manifest_path(
    packet_root: Path,
    tmp_path: Path,
) -> None:
    registry = _registry(packet_root)
    registry["packets"][0]["manifest_path"] = "../event_manifest.json"
    _write_registry(packet_root, registry)

    with pytest.raises(RuntimeError, match="Unsafe packet manifest path"):
        _packet_validator(tmp_path)(packet_root)
