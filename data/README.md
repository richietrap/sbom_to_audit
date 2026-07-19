# Data Directory

This directory contains committed controlled inputs and frozen public-feed-shaped snapshots.

- `sbom/` — CycloneDX or SPDX artefacts;
- `csaf/` — CSAF/VEX advisories;
- `osv_snapshots/` — frozen OSV response shapes;
- `nvd_snapshots/` — optional NVD comparison snapshots;
- `kev_snapshots/` — frozen CISA KEV catalogue shapes;
- `epss_snapshots/` — frozen FIRST EPSS response shapes;
- `telemetry/` — controlled local runtime and reachability records;
- `asset_context/` — controlled asset criticality and deployment scope;
- `mitigation/` — controlled remediation and verification records;
- `decision_records/` — conflict adjudication, human authorization, and milestone evidence;
- `scenarios/` — replay manifests that release artefacts over time.

Ghost-Logger files are fictional but use representative machine-readable structures. They must not be described as public intelligence, industrial incident data, or an official vendor advisory. Public historical replay data will be stored separately and labelled by provenance and redistribution status.

The scenario YAML must not contain source hashes or normalized results. Hashes are computed by the source registry at runtime.
