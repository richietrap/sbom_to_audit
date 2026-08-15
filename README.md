# sbom-to-audit

Research artefact for **“From SBOM to Audit: Temporal Vulnerability-Evidence Orchestration for NIS2 and Cyber Resilience Act Reporting.”**

GitHub is the source of truth. Google Colab is the independent clean-room runtime; Google Drive may preserve generated outputs and cached snapshots.

## Status

Version 0.6.5 is the Stage 6.5 independent-audit remediation candidate. It preserves the accepted Stage 6.4 source and observed evidence as immutable history while addressing the two MAJOR Stage 6.5 findings: Audit Reconstructability now conforms to the frozen `output_hash OR output_state` specification, and a complete performance rerun preserves one genuine worker-level high-water RSS observation per workload for independent raw recomputation. Historical Stage 6.3 mutation evidence remains bound to its original source hashes rather than being rewritten to fit the changed AR source. Targeted independent closure re-audit has resolved `S65-F001` and `S65-F004`; Stage 6.5 nevertheless remains `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false` pending post-audit repository integration, GitHub Actions, exact-commit Colab reproduction, the deferred manual baseline, and final evaluation freeze.

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
python scripts/run_baseline_comparison.py \
  --output-root outputs/stage6_baseline
python paper_assets/scripts/build_stage6_assets.py \
  --output-root outputs/stage6_baseline \
  --destination paper_assets
python scripts/freeze_stage6_1_protocol.py --verify
python scripts/validate_stage6_1_evaluation.py
python scripts/validate_manual_baseline_worksheet.py data/baseline_templates
python scripts/export_stage6_1_baseline_packets.py \
  --destination /tmp/stage6_1_baseline_packets
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

The historical EPSS record is subject to a mandatory online API/archive verification gate.

## Stage 5.5.1 historical EPSS verification — rejected candidate

The first online run rejected the prefilled normalized score and percentile. The failed run is retained as development evidence that the fail-closed gate worked and must not be cited as a verified result. The CVE-2024-3400 replay uses a fail-closed verification contract for the
2024-04-15 EPSS record. The GitHub quality workflow and isolated Colab
checkpoint independently download the date-specific FIRST API response and a
pinned official daily archive, compare the CVE/date/score/percentile and verify
the archive model metadata. Raw authoritative evidence is retained in the
Colab checkpoint bundle. A matched ablation confirms that omitting EPSS does not
change the historical reference state trajectory.

Run the offline contract check with:

```bash
python scripts/verify_historical_epss.py
```

The online acceptance gate is:

```bash
python scripts/verify_historical_epss.py --online --output-dir /tmp/epss-verification
```

## Stage 5.5.2 historical EPSS correction

The Stage 5.5.1 online gate correctly rejected the prefilled candidate values.
The date-specific FIRST API response and pinned daily archive agreed on:

```text
EPSS       0.00371
percentile 0.72343
model      v2023.03.01
```

Stage 5.5.2 updates the normalized fixtures and keeps the same mandatory online
gate. Failed verification now preserves raw downloads and a structured
diagnostic report. Mutable API/archive downloads must remain under
`outputs/validation` or in a checkpoint bundle; repository-root copies are
ignored and rejected by repository validation.
## Stage 6 matched baseline comparison

`evaluation/baseline_protocol_v0.1.yaml` defines a deterministic structured-but-unorchestrated PSIRT worksheet proxy. It receives the same source bytes, release chronology, validation, and parser-derived observations as the artefact. It retains source registers, deadline tracking, authorization, and event logs, but does not use the claim graph, scope-overlap engine, numerical orchestration variables, conflict lifecycle, automatic `tau_E` safeguard, or EvidencePack generation.

Across the four primary controlled families, the pilot comparison reports higher artefact values for EC, TR, CA, SC, and EPG; equal AR and seeded-conflict recall; and higher conflict precision once the scope-blind False Comfort baseline false positive is counted. These are controlled functional results, not evidence of human time savings, legal correctness, or industrial effectiveness.


## Stage 6.1 hardened manual-assisted baseline

`evaluation/baseline_protocol_v0.2.yaml` defines the pre-registered manual-assisted comparison. The analyst receives the same scenario releases and may use ordinary inspection tools, but does not receive the prototype, generated claims, automated scores, conflict reports, or expected-state oracles. The completed worksheet records analyst confidence, source access, decisions, conflicts, and elapsed review time.

Independent state, conflict, and clock-opportunity oracles are stored under `evaluation/oracles/` and are hashed with the protocol, mappings, worksheet schema, and scenario files in `evaluation/freeze/stage6_1_protocol_freeze.json`. The seven locked metrics and EvidencePack v0.2 remain unchanged. Common-field completeness, partial lineage, equivalent record-bundle generation, like-for-like source-access accounting, conflict precision, and human Time to Decision are supplemental fairness controls.

Stage 6.1 is currently an implementation candidate awaiting genuine manual execution. The blank workbook is `data/baseline_templates/manual_psirt_worksheet.xlsx`; the canonical exchange files are the adjacent CSV/YAML templates. The final Colab checkpoint rejects mutable branch references such as `main`.
## Stage 6.2 robustness and sensitivity evaluation

Stage 6.2 adds a deterministic robustness harness for threshold, clock, identity, exploitation, applicability, scope, mitigation, conflict, missingness, malformed-input, and temporal-integrity perturbations. It preserves EvidencePack Schema v0.2, the 34-field EC denominator, the seven locked metrics, the accepted scenario evidence, and the Stage 6.1 pre-execution freeze.

Candidate outputs are stored under `evaluation/stage6_2_candidate/` and candidate figures and tables are generated from those machine-readable results. They remain `CANDIDATE_NOT_FROZEN` and are not manuscript-eligible until GitHub, exact-commit Colab reproduction, independent review, and the final evaluation freeze. The blinded manual baseline is deferred but still required before final RQ5 comparative claims.

## Stage 6.3 controlled mutation testing

Stage 6.3 evaluates whether the verification system detects plausible faults in temporal decision logic, conflict handling, authorisation, source integrity, identity uncertainty, evidence semantics, and metric computation. Mutants are pre-registered, first order, exact-text, and applied one at a time in a temporary repository copy. Baseline survivors and the targeted tests added in response remain separately recorded. A bounded mutation score is not represented as proof of exhaustive correctness or absence of defects.

## Stage 6.5 audit remediation

Stage 6.5 remediation is intentionally narrow. `S65-F001` corrects only the Audit Reconstructability output-identification predicate so the common audit fields remain mandatory while either a populated `output_hash` or `output_state` satisfies the frozen output-identification requirement. The historical Stage 6.3 exact-text mutation protocol and result bundle are not rewritten; current v0.6.5 AR behaviour is covered by new specification-derived regression tests.

`S65-F004` is addressed by a new performance protocol v0.2 and a separate Stage 6.5 candidate run. The runner preserves the same four scale axes, five workloads per axis, three warm-ups and ten measured replays per workload. Because the operating-system measurement is `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss` captured after the workload worker completes its warm-ups and measured runs, the raw memory evidence contains one genuine high-water RSS observation per workload worker rather than pseudo per-trial observations. The historical Stage 6.4 protocol v0.1, results, and F12/T30/T31 assets remain unchanged.

The v0.2 protocol also makes the previously implicit Stage 6.4 coefficient-of-variation convention explicit: `wall_cv = statistics.stdev(wall) / statistics.fmean(wall)`, using sample standard deviation with an `n-1` denominator. This is a versioned clarification, not a claim that v0.1 documented the convention explicitly.

Development tests did not close the MAJOR findings. A targeted independent closure re-audit subsequently resolved both `S65-F001` and `S65-F004`, with closure evidence bundle SHA-256 `1c03387e3dfbc5e3bee4e115cca8d2a93ba0a5f17602f0b5ab950502be9530c8`. This closure does not itself freeze or accept the repository: the candidate remains manuscript-ineligible until the post-audit repository/GitHub/exact-commit-Colab sequence and final evaluation freeze are completed.

## Stage 6.4 performance and scale evaluation

Stage 6.4 characterizes the computational behaviour of the accepted orchestration path without changing production thresholds or scenario oracles. The registered protocol scales four dimensions independently: CycloneDX component count, runtime-telemetry record count, registered source-artifact count, and replay-event count. A fresh worker process is used for each workload; warm-up runs are excluded; measured runs report median and nearest-rank p95 wall time, CPU time, peak resident memory, input/output size, relative slowdown, and scale-unit throughput.

Scale fixtures extend the controlled Ghost-Logger case with deterministic decoys or no-op temporal events. Every workload must preserve the unscaled final state, authorized state, orchestration scores, and the registered outcomes of the original five events. The benchmark has no pass/fail latency threshold. Hardware-specific values must be reported with their environment metadata and must not be pooled across non-equivalent environments.
