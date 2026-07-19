from copy import deepcopy
from pathlib import Path

import pytest

from sbom_to_audit.ingestion.source_registry import SourceRegistry
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "ghost_logger.yaml"


def _scenario() -> dict:
    value = read_yaml(SCENARIO)
    assert isinstance(value, dict)
    return value


def test_registry_computes_hashes_and_validates_all_sources() -> None:
    scenario = _scenario()
    registry = SourceRegistry(ROOT, target_cve=scenario["target"]["cve_id"])
    registry.register_catalog(scenario["source_catalog"])
    manifest = registry.manifest()
    assert manifest["source_count"] == 15
    assert all(item["validation_status"] == "valid" for item in manifest["sources"])
    assert all(len(item["source_hash"]) == 64 for item in manifest["sources"])
    assert all(item["size_bytes"] > 0 for item in manifest["sources"])


def test_registry_rejects_missing_source() -> None:
    scenario = _scenario()
    spec = deepcopy(scenario["source_catalog"][0])
    spec["path"] = "data/sbom/does-not-exist.json"
    registry = SourceRegistry(ROOT, target_cve=scenario["target"]["cve_id"])
    with pytest.raises(FileNotFoundError):
        registry.register(spec)


def test_registry_rejects_path_escape() -> None:
    scenario = _scenario()
    spec = deepcopy(scenario["source_catalog"][0])
    spec["path"] = "../outside.json"
    registry = SourceRegistry(ROOT, target_cve=scenario["target"]["cve_id"])
    with pytest.raises(ValueError, match="escapes repository root"):
        registry.register(spec)
