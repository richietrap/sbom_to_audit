import json
from pathlib import Path

import pytest

from sbom_to_audit.parsers.asset_context_parser import parse_asset_context
from sbom_to_audit.parsers.csaf_parser import parse_csaf
from sbom_to_audit.parsers.cyclonedx_parser import parse_cyclonedx
from sbom_to_audit.parsers.epss_client import extract_percentile, query_epss
from sbom_to_audit.parsers.kev_client import kev_entry, load_kev_catalog
from sbom_to_audit.parsers.nvd_client import extract_cvss_metrics
from sbom_to_audit.parsers.osv_client import cve_aliases, query_osv
from sbom_to_audit.parsers.telemetry_parser import execution_observed, parse_telemetry

ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_cyclonedx_and_csaf_parsers(tmp_path: Path) -> None:
    bom = write_json(
        tmp_path / "bom.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:test",
            "metadata": {"component": {"name": "root", "version": "1"}},
            "components": [
                {
                    "bom-ref": "lib@1",
                    "type": "library",
                    "name": "lib",
                    "version": "1",
                    "purl": "pkg:pypi/lib@1",
                }
            ],
        },
    )
    parsed_bom = parse_cyclonedx(bom)
    assert parsed_bom["components"][0]["purl"] == "pkg:pypi/lib@1"

    csaf = write_json(
        tmp_path / "csaf.json",
        {
            "document": {"category": "csaf_vex", "tracking": {"id": "ADV-1"}},
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "product_status": {"known_affected": ["product-1"]},
                }
            ],
        },
    )
    parsed_csaf = parse_csaf(csaf)
    assert parsed_csaf["document_tracking_id"] == "ADV-1"
    assert parsed_csaf["vulnerabilities"][0]["product_status"]["known_affected"] == ["product-1"]


def test_asset_and_telemetry_parsers(tmp_path: Path) -> None:
    asset_json = write_json(tmp_path / "asset.json", {"asset_criticality": "high"})
    assert parse_asset_context(asset_json)["asset_criticality"] == "high"

    asset_yaml = tmp_path / "asset.yaml"
    asset_yaml.write_text("deployment_scope: limited\n", encoding="utf-8")
    assert parse_asset_context(asset_yaml)["deployment_scope"] == "limited"

    telemetry = tmp_path / "events.jsonl"
    telemetry.write_text(
        '{"execution_observed": false}\n{"execution_observed": true}\n',
        encoding="utf-8",
    )
    records = parse_telemetry(telemetry)
    assert execution_observed(records) is True

    malformed = tmp_path / "bad.jsonl"
    malformed.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSONL"):
        parse_telemetry(malformed)


def test_offline_public_intelligence_helpers(tmp_path: Path) -> None:
    osv_path = write_json(
        tmp_path / "osv.json",
        {"vulns": [{"aliases": ["CVE-2026-0001", "GHSA-test"]}]},
    )
    osv = query_osv(snapshot_path=osv_path, offline=True)
    assert cve_aliases(osv) == ["CVE-2026-0001"]

    kev_path = write_json(
        tmp_path / "kev.json",
        {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
    )
    kev = load_kev_catalog(snapshot_path=kev_path, offline=True)
    assert kev_entry(kev, "CVE-2026-0001") is not None
    assert kev_entry(kev, "CVE-2026-9999") is None

    epss_path = write_json(tmp_path / "epss.json", {"data": [{"percentile": "0.91"}]})
    epss = query_epss("CVE-2026-0001", snapshot_path=epss_path, offline=True)
    assert extract_percentile(epss) == 0.91
    assert extract_percentile({"data": []}) is None


def test_nvd_cvss_metric_extraction() -> None:
    snapshot = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0002",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "example",
                                "cvssData": {
                                    "baseScore": 6.5,
                                    "baseSeverity": "MEDIUM",
                                    "vectorString": "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H",
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }
    metrics = extract_cvss_metrics(snapshot, "CVE-2026-0002")
    assert metrics is not None
    assert metrics["base_score"] == 6.5
    assert metrics["base_severity"] == "MEDIUM"
    assert extract_cvss_metrics(snapshot, "CVE-2026-9999") is None

    snapshot["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = 11.0
    with pytest.raises(ValueError, match="between 0 and 10"):
        extract_cvss_metrics(snapshot, "CVE-2026-0002")


def test_cyclonedx_name_version_identity_and_bom_ref_path() -> None:
    from sbom_to_audit.parsers.cyclonedx_parser import (
        component_by_name_version,
        dependency_path_by_bom_ref,
        parse_cyclonedx,
    )

    document = parse_cyclonedx(ROOT / "data" / "sbom" / "rapid_pivot.cdx.json")
    component = component_by_name_version(document, "session-router", "3.1.4")
    assert component is not None
    assert component["bom_ref"] == "component:session-router:3.1.4"
    assert component["purl"] is None
    assert dependency_path_by_bom_ref(document, component["bom_ref"]) == [
        "product:remote-operations-console:5.8.0",
        "pkg:npm/remote-session-core@6.0.0",
        "component:session-router:3.1.4",
    ]
