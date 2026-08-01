import ast
import importlib.util
import json
import stat
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "stage6_1_5_colab_checkpoint.ipynb"


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


def _safe_extract(tmp_path: Path) -> Callable[[Path, Path], None]:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    source = _cell_source(notebook["cells"][6])
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "safe_extract_zip"
    )
    module_source = (
        "import re\n"
        "import stat\n"
        "import zipfile\n"
        "from pathlib import Path, PurePosixPath\n\n"
        "MAX_MANUAL_ZIP_MEMBERS = 200\n"
        "MAX_MANUAL_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024\n\n"
        + ast.unparse(function)
        + "\n"
    )
    module = _load_module(tmp_path / "notebook_safe_extract.py", module_source)
    return module.safe_extract_zip


def test_stage6_1_5_safe_zip_extracts_regular_files(tmp_path: Path) -> None:
    source = tmp_path / "manual.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("bundle/", "")
        archive.writestr("bundle/declaration.yaml", "protocol_version: '0.2'\n")
        archive.writestr("bundle/data.csv", "a,b\n1,2\n")

    destination = tmp_path / "extracted"
    _safe_extract(tmp_path)(source, destination)

    assert (destination / "bundle" / "declaration.yaml").is_file()
    assert (destination / "bundle" / "data.csv").read_text(encoding="utf-8") == "a,b\n1,2\n"


@pytest.mark.parametrize(
    "member",
    ["../escape.txt", "/absolute.txt", "C:/drive.txt", "bundle\\escape.txt"],
)
def test_stage6_1_5_safe_zip_rejects_unsafe_paths(tmp_path: Path, member: str) -> None:
    source = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(member, "unsafe")

    with pytest.raises(ValueError, match="ZIP path|Drive-qualified|Backslash"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_duplicate_raw_paths(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("bundle/data.csv", "first")
            archive.writestr("bundle/data.csv", "second")

    with pytest.raises(ValueError, match="duplicate normalized paths"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_noncanonical_path_aliases(tmp_path: Path) -> None:
    source = tmp_path / "aliases.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("bundle/data.csv", "first")
        archive.writestr("bundle//data.csv", "second")

    with pytest.raises(ValueError, match="non-canonical ZIP path"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_file_parent_collision(tmp_path: Path) -> None:
    source = tmp_path / "collision.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("bundle", "file")
        archive.writestr("bundle/declaration.yaml", "protocol_version: '0.2'\n")

    with pytest.raises(ValueError, match="nested below another file"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_symbolic_links(tmp_path: Path) -> None:
    source = tmp_path / "symlink.zip"
    member = zipfile.ZipInfo("bundle/link")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(member, "../../outside")

    with pytest.raises(ValueError, match="Symbolic links"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_special_files(tmp_path: Path) -> None:
    source = tmp_path / "special.zip"
    member = zipfile.ZipInfo("bundle/fifo")
    member.create_system = 3
    member.external_attr = (stat.S_IFIFO | 0o600) << 16
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(member, "")

    with pytest.raises(ValueError, match="Special files"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_corrupt_member(tmp_path: Path) -> None:
    source = tmp_path / "corrupt.zip"
    payload = b"unique-corruption-probe"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("bundle/data.bin", payload)
    raw = bytearray(source.read_bytes())
    position = raw.find(payload)
    assert position >= 0
    raw[position] ^= 0xFF
    source.write_bytes(raw)

    with pytest.raises(ValueError, match="corrupt member|integrity validation failed"):
        _safe_extract(tmp_path)(source, tmp_path / "extracted")


def test_stage6_1_5_safe_zip_rejects_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "manual.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("bundle/declaration.yaml", "protocol_version: '0.2'\n")
    destination = tmp_path / "extracted"
    destination.mkdir()

    with pytest.raises(FileExistsError, match="already exists"):
        _safe_extract(tmp_path)(source, destination)
