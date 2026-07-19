# From SBOM to Audit

**Temporal vulnerability-evidence orchestration for NIS2 and Cyber Resilience Act reporting**

`sbom-to-audit` is a Design Science Research proof-of-concept that turns fragmented product-security evidence into time-indexed, auditable decision-support records. It is being developed for the C&ESAR 2026 paper **“From SBOM to Audit: Temporal Vulnerability-Evidence Orchestration for NIS2 and Cyber Resilience Act Reporting.”**

The repository is the source of truth. Google Colab is the intended runtime environment, while Google Drive may be used for persistent generated outputs and cached public-source snapshots.

## Status

This repository implements the locked EvidencePack Schema v0.2 scaffold and an executable controlled replay for the fictional **Silent Transitive / Ghost-Logger** scenario. The paper has been shortlisted for C&ESAR 2026 final selection; it is not yet an accepted final paper.

## Research questions

- **RQ1.** What evidence artifacts are required to support defensible reportability decisions for actively exploited vulnerabilities and severe product-security incidents?
- **RQ2.** How can SBOM, VEX/CSAF, CVE, KEV, EPSS, reachability, telemetry, asset-context, and PSIRT records be normalized and linked into an auditable evidence chain?
- **RQ3.** How can reportability be operationalized as a temporal state transition with explicit uncertainty, mitigation, impact, identity-confidence, regulatory-clock, and conflict-handling mechanisms?
- **RQ4.** Can a proof-of-concept implementation ingest real security-data formats and public vulnerability-intelligence sources to generate auditable evidence packs and state-transition logs?
- **RQ5.** To what extent does the implemented artefact improve evidence completeness, traceability, conflict detection, clock-aware escalation, and audit reconstructability compared with an un-orchestrated PSIRT workflow?

## Model boundary

The artefact is an evidence-orchestration and decision-support layer. It is **not**:

- a legal-reporting engine;
- a production PSIRT platform;
- an automatic regulatory-submission tool; or
- a complete solution to PURL/CPE identity matching.

It may recommend `Report-Ready`, but only human review can authorize `Report` or `Document No-Report`.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
python -m pip install -e .[dev]
python -m sbom_to_audit.cli --scenario data/scenarios/ghost_logger.yaml
pytest
```

Expected replay outputs:

```text
outputs/evidence_packs/ghost_logger.json
outputs/state_logs/ghost_logger.csv
outputs/conflict_reports/ghost_logger.json
outputs/metrics/ghost_logger_metrics.json
```

The replay is deterministic: timestamps and seeded evidence values come from the scenario file rather than wall-clock execution time.

## Repository map

- `docs/` — design freeze, schema, metric definitions, reproduction, and replay protocol.
- `schemas/` — JSON Schema for EvidencePack v0.2.
- `src/sbom_to_audit/` — parsers, identity handling, scoring, state machine, pack generation, and metrics.
- `data/` — controlled inputs and cached public-source snapshots.
- `outputs/` — generated evidence packs, state logs, conflict reports, and metrics.
- `tests/` — unit tests for the locked identity, scoring, state, and metric rules.
- `MANIFEST.md` — drift-control inventory of every expected repository file.

## Initial prototype rules

The locked state function is:

```text
R_t = f(E_t, A_t, I_t, M_t, U_t, C_t, delta_t)
```

Conflict has precedence. A prior `Prepare` state escalates at `delta_t >= 18h`. The 18-hour value is an internal PSIRT safeguard before a 24-hour reporting window, not legal advice.

See [`docs/design_freeze_v0.2.md`](docs/design_freeze_v0.2.md) for the complete frozen specification and [`docs/metrics.md`](docs/metrics.md) for the seven evaluation metrics.

## Baseline

The comparison baseline is a conventional un-orchestrated PSIRT workflow in which an analyst separately checks SBOMs, advisories, VEX status, KEV, EPSS, reachability, telemetry, asset criticality, and mitigation records, then manually records the rationale. The baseline does not imply poor practice; it is the comparator for measuring the effect of orchestration.

## License and citation

Code is released under the MIT License. Citation metadata is provided in `CITATION.cff`.
