# sbom-to-audit

Research artefact for **“From SBOM to Audit: Temporal Vulnerability-Evidence Orchestration for NIS2 and Cyber Resilience Act Reporting.”**

GitHub is the source of truth. Google Colab is the independent clean-room runtime; Google Drive may preserve generated outputs and cached snapshots.

## Status

Version 0.5.0 implements Stage 5 Rapid Pivot while preserving Ghost-Logger, False Comfort, and Operational Outlier. It adds evidence-derived fuzzy identity fallback, explicit CPE-confirmed identity resolution, intermediate missing-evidence handling, clock-safeguard audit fields, and a matched early-resolution temporal control. All cases remain fictional and must not be described as industrial case studies.

## Research questions

- **RQ1.** What evidence artefacts are required to support defensible reportability decisions for actively exploited vulnerabilities and severe product-security incidents?
- **RQ2.** How can SBOM, VEX/CSAF, CVE, KEV, EPSS, reachability, telemetry, asset-context, and PSIRT records be normalized and linked into an auditable evidence chain?
- **RQ3.** How can reportability be operationalized as a temporal state transition with explicit uncertainty, mitigation, impact, identity-confidence, regulatory-clock, and conflict-handling mechanisms?
- **RQ4.** Can a proof-of-concept implementation ingest real security-data formats and public vulnerability-intelligence sources to generate auditable evidence packs and state-transition logs?
- **RQ5.** To what extent does the implemented artefact improve evidence completeness, traceability, conflict detection, clock-aware escalation, and audit reconstructability compared with an un-orchestrated PSIRT workflow?

## Model boundary

The artefact is an evidence-orchestration and decision-support layer. It is not a legal-reporting engine, production PSIRT platform, automatic submission tool, or complete PURL/CPE identity-resolution solution.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
python -m pip install -e ".[dev]"
python scripts/validate_repository.py --strict-sources
for scenario in data/scenarios/*.yaml; do
  python -m sbom_to_audit.cli --scenario "$scenario"
done
python paper_assets/scripts/build_stage2_assets.py \
  --output-root outputs \
  --destination paper_assets
python paper_assets/scripts/build_stage3_assets.py \
  --output-root outputs \
  --destination paper_assets
python paper_assets/scripts/build_stage4_assets.py \
  --output-root outputs \
  --destination paper_assets
python paper_assets/scripts/build_stage5_assets.py \
  --output-root outputs \
  --destination paper_assets
python -m pytest
python scripts/release_check.py
```

## Deterministic outputs

```text
outputs/evidence_packs/ghost_logger.json
outputs/state_logs/ghost_logger.csv
outputs/conflict_reports/ghost_logger.json
outputs/metrics/ghost_logger_metrics.json
outputs/source_manifests/ghost_logger_sources.json
outputs/audit_ledgers/ghost_logger.jsonl
```

The source registry computes hashes from files; the scenario contains no source hashes, normalized claims, or precomputed scores.

## Pilot trajectory

```text
T+2h   Document No-Report
T+10h  Escalate
T+14h  Report-Ready
T+20h  Report-Ready + authorized_state=Report
T+72h  Report-Ready + completed milestone evidence
```

The distinction between `Report-Ready` and human-authorized `Report` is intentional. The T+10h affectedness conflict is retained as historical evidence and explicitly marked `resolved` at T+14h.

## Stage 3 scope-aware scenarios

- **Ghost-Logger:** overlapping supplier and local affectedness claims produce an intentional conflict, escalation, and explicit resolution lifecycle.
- **False Comfort:** a `known_not_affected` supplier assertion is valid for `standard-profile` but does not apply to the active `legacy-plugin-profile`; later deployment-specific reachability produces `Report-Ready`.
- **False Comfort negative control:** the same assertion applies to a matching `standard-profile` deployment and produces `Document No-Report` when no local reachability or execution is observed.

Scope reasoning is generic application logic. No scenario identifier or product name is embedded in `src/`.

## Stage 4 operational-impact scenario

- **Operational Outlier:** a CVSS 6.5 MEDIUM vulnerability is KEV-listed and reachable in a critical, widespread operational deployment; the case reaches `Report-Ready` once applicability is confirmed.
- **Counterfactual lower-impact control:** the same non-asset source files, deployment identity, timestamps, and deadline profile are replayed with only `asset_criticality=medium` and `deployment_scope=limited`; the case remains `Monitor`.

The comparison preserves technical severity as contextual evidence and isolates the configured impact mechanism. `under_investigation` is retained as a supplier-assessment status rather than misrepresented as a not-affected conclusion.

## Stage 5 uncertainty and clock-aware escalation

- **Rapid Pivot:** KEV and high operational-impact context are available, but EPSS, VEX, telemetry and strong component identity evidence are initially missing. The case enters `Prepare`, remains unresolved, and reaches `Escalate` at the internal `tau_E=18h` safeguard.
- **Early-resolution control:** byte-identical sources, target, deadline profile and event timestamps are used, but the same uncertainty-resolving evidence is released at T+12h. The case reaches `Report-Ready` before T+18h and does not trigger clock escalation.

The initial `gamma_id=0.4` is derived from a unique name/version SBOM candidate whose PURL is absent. A later, validated CPE-confirmation artefact changes the matching method to `exact_cpe_confirmed` and `gamma_id=0.7`. The 18-hour safeguard remains an internal PSIRT control and must not be described as a statutory deadline.

## Research-evidence accumulation

- `evaluation/` records scenarios, runs, environments, and derived summaries;
- `paper_assets/` contains data-driven pilot figures and tables;
- `docs/paper_asset_protocol.md` defines when an asset becomes eligible for the manuscript;
- `MANIFEST.md` controls repository drift.

Pilot assets are not final paper results. They must be regenerated from a tagged GitHub commit and reproduced in Colab.

## License and citation

Code is released under the MIT License. Citation metadata is provided in `CITATION.cff`.


## Stage 5.5 historical replay

The repository now includes a CVE-2024-3400 / Operation MidnightEclipse historical reconstruction.
`data/historical_replays/cve_2024_3400/` contains public-source fact extracts, a source registry,
and a chronology that prevents retrospective occurrence dates from being treated as earlier public
knowledge. `scripts/run_historical_replay.py` generates a public-only evidence bundle without
fabricating organisation-local facts.

`data/scenarios/historical_cve_2024_3400_reference.yaml` is a separate synthetic reference
deployment that exercises the full EvidencePack pipeline. It is not a fifth controlled scenario
family and must not be interpreted as evidence about a real organisation.

The historical EPSS reconstruction remains provisional and blocks manuscript eligibility.
