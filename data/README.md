# Data Directory

This directory separates checked-in controlled inputs from cached public-source snapshots.

- `sbom/` — CycloneDX or SPDX source artifacts.
- `csaf/` — CSAF/VEX advisories.
- `osv_snapshots/` — frozen OSV API responses.
- `nvd_snapshots/` — optional NVD snapshots retained for comparison, not the primary identity bridge.
- `kev_snapshots/` — frozen CISA KEV catalog responses.
- `epss_snapshots/` — frozen FIRST EPSS responses.
- `telemetry/` — controlled local execution or reachability records.
- `asset_context/` — controlled asset criticality and deployment-scope records.
- `mitigation/` — controlled patch, workaround, and verification records.
- `scenarios/` — replay manifests that bind the evidence into expected temporal trajectories.

Do not commit confidential customer, incident, or corporate PSIRT data. Public-source snapshots used in the paper should include retrieval timestamps and SHA-256 hashes.
