# Data Directory

This directory contains committed controlled inputs and frozen public-feed-shaped snapshots.

- `sbom/` — CycloneDX or SPDX artefacts;
- `csaf/` — CSAF/VEX advisories;
- `osv_snapshots/` — frozen OSV response shapes;
- `nvd_snapshots/` — frozen NVD API 2.0 response shapes used for contextual CVSS evidence;
- `kev_snapshots/` — frozen CISA KEV catalogue shapes;
- `epss_snapshots/` — frozen FIRST EPSS response shapes;
- `telemetry/` — controlled local runtime and reachability records;
- `asset_context/` — controlled asset criticality and deployment scope;
- `mitigation/` — controlled remediation and verification records;
- `decision_records/` — conflict adjudication, human authorization, and milestone evidence;
- `scenarios/` — replay manifests that release artefacts over time.

Ghost-Logger files are fictional but use representative machine-readable structures. They must not be described as public intelligence, industrial incident data, or an official vendor advisory. Public historical replay data will be stored separately and labelled by provenance and redistribution status.

The scenario YAML must not contain source hashes or normalized results. Hashes are computed by the source registry at runtime.

## False Comfort source family

The False Comfort files are controlled fictional artefacts. The CSAF product helper declares `standard-profile` through a model number; the primary asset and telemetry declare `legacy-plugin-profile`, while the negative-control asset declares `standard-profile`. These values are source data, not precomputed orchestration conclusions.

## Operational Outlier source family

The Operational Outlier files are controlled fictional artefacts. The primary and negative-control replays share the same SBOM, OSV, NVD-shaped CVSS, KEV, EPSS, CSAF, and reachability evidence. Their asset-context files intentionally differ in criticality and deployment scope so the frozen `I_t` mechanism can be tested without changing technical severity or applicability.

## Rapid Pivot source family

The Rapid Pivot files are controlled fictional artefacts. The CycloneDX component intentionally omits a PURL but includes a unique normalized name/version and CPE. Initial replay events release no EPSS, CSAF/VEX, telemetry, or identity-confirmation source, allowing intermediate missingness to be measured by the frozen uncertainty equation. A later identity-resolution record confirms the canonical component PURL through the selected component's exact CPE. The main and temporal-control scenarios reuse the same source catalog and differ only in when the resolving artefacts are released.


## Historical replay data

`historical_replays/cve_2024_3400/` separates normalized public fact extracts from a synthetic
reference deployment. Public files retain upstream URLs and temporal metadata. Reference-deployment
files are explicitly fictional. Do not move them into the controlled scenario folders without
preserving their classification.

### Historical EPSS verification

`data/historical_replays/cve_2024_3400/epss/` contains the normalized expected
record and pinned dual-source verification contract. Raw API and gzip files are
not committed; the mandatory online gates download them and the Colab evidence
bundle preserves them with hashes.
