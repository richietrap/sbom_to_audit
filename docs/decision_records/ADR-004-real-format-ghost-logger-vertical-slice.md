# ADR-004: Real-Format Ghost-Logger Vertical Slice

- **Status:** Accepted for Stage 2 pilot
- **Date:** 2026-07-19
- **EvidencePack schema:** unchanged at v0.2
- **Package version:** 0.2.3

## Context

The earlier scaffold embedded normalized claims, hashes, identity results, and evidence values in `ghost_logger.yaml`. That structure could test the state rule but could not substantiate RQ4's real-format ingestion claim.

## Decision

Ghost-Logger is converted into a source-catalog replay manifest. The implementation now derives evidence from committed CycloneDX, CSAF/VEX, OSV-shaped, KEV-shaped, EPSS-shaped, telemetry, asset, mitigation, adjudication, authorization, and milestone-evidence artefacts.

The source registry:

- confines paths to the repository;
- validates source types;
- computes SHA-256 from files;
- records parser, media type, size, and validation status;
- rejects missing, duplicate, unsupported, or path-escaping sources.

The pipeline derives claims and evidence variables from released artefacts. Earlier observations in the same evidence class and scope are superseded temporally, while cross-class contradictions persist until an explicit adjudication record resolves them.

## Consequences

- the scenario YAML no longer contains claims, hashes, scores, or conflict results;
- six deterministic output products are generated;
- the full five-event Ghost-Logger trajectory is executable;
- final recommendation is `Report-Ready` and human authorization is separately `Report`;
- source and paper-asset registries are introduced;
- the result remains a pilot controlled fictional replay, not industrial validation.

## Schema and metric impact

EvidencePack Schema v0.2, the 34 mandatory fields, and EC/TR/CD/CA/AR/SC/EPG remain unchanged. Source-integrity, authorization-correctness, and deadline-correctness values are supplemental sidecar measures.

## Affected modules

- `src/sbom_to_audit/ingestion/*`;
- CycloneDX, CSAF, and telemetry parsers;
- conflict engine, EvidencePack builder, CLI, repository validator, and release check;
- Ghost-Logger data and scenario files;
- integration, source-registry, parser, and pipeline tests;
- evaluation and paper-asset registries.
