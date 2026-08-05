## 0.6.2 — Stage 6.2 robustness and sensitivity evaluation — 2026-08-03

- added a registered Stage 6.2 threshold, clock, single-factor, and negative-case protocol;
- added deterministic robustness runner, validator, output manifest, and scenario-stability summary;
- added a data-driven paper asset builder with two SVG figures and five CSV tables;
- added an isolated exact-commit Stage 6.2 Colab checkpoint with double-run byte comparison;
- added fail-closed chronology checks for duplicate, out-of-order, pre-clock, and future-source events;
- added Stage 6.2 unit, integration, validator, asset, temporal-integrity, and notebook-contract tests;
- preserved EvidencePack Schema v0.2, the 34-field EC denominator, locked metrics, accepted scenario evidence, and the Stage 6.1 freeze;
- recorded all results and paper assets as `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false`;
- documented BUG-027 as the pre-acceptance Stage 6.1.5 formatter correction and BUG-028 as a Stage 6.2 pre-release temporal-integrity correction.

# Changelog

## 0.6.1.5 — Stage 6.1.5 isolated Colab checkpoint correction — 2026-07-30

- Corrected the Stage 6.1.4 checkpoint's use of the shared Colab kernel environment for package installation, dependency integrity, validation, tests, replay, and export commands.
- Restored a dedicated virtual environment and routed every repository command through its explicit interpreter.
- Replaced the fail-first reference placeholder with an exact 40-character commit-SHA prompt and detached-checkout equality verification.
- Added complete named command logs, retry handling for network-dependent installation and historical verification, safe manual ZIP extraction, output cleanup, evidence-content checksums, and checkpoint ZIP integrity verification.
- Restored authoritative online historical EPSS verification and verified historical replay generation in the Stage 6.1 checkpoint.
- Added `scripts/validate_stage6_1_colab_notebook.py`, notebook code-cell compilation, release-contract tests, ADR-021, BUG-022, and a Stage 6.1.5 correction report.
- Corrected the pre-release notebook validator to normalise canonical nbformat source arrays before compilation and contract scanning; added negative regression tests and recorded the internally detected defect as BUG-023.
- Corrected pre-release manual ZIP member-type handling after notebook-derived tests found that ordinary ZIP entries without explicit Unix file-type bits were incorrectly rejected; recorded as BUG-024.
- Hardened the pre-release manual ZIP path after adversarial review found normalized path aliases, file-parent collisions, and bulk extraction remained insufficiently constrained; replaced it with exclusive streamed extraction and recorded BUG-025.
- Added notebook-derived tests for regular, traversal, absolute, drive-qualified, duplicate, symbolic-link, and special-file ZIP entries, plus retry-log preservation tests.
- Added independent packet-registry, manifest-hash, copied-artifact-hash, identity, path, and recursive blinding-key verification after the pre-release audit identified the missing checkpoint boundary; recorded as BUG-026.
- Preserved the Stage 6.1 protocol freeze, independent oracles, fairness mappings, EvidencePack v0.2, the 34-field EC denominator, all seven locked metrics, and the manuscript-eligibility boundary.

## 0.6.1.4 — Stage 6.1.4 YAML-quality and release-gate parity correction — 2026-07-29

- Corrected all Yamllint indentation errors reported across the Stage 6.1 protocol, independent oracles, fairness mappings, analyst allowed-tool policy, and seven chronological release manifests.
- Removed the excess trailing blank line from `.github/workflows/tests.yml`.
- Verified parsed YAML semantic equivalence before and after canonical indentation for all 17 affected YAML or workflow files.
- Refreshed the byte-level Stage 6.1 pre-execution freeze as `STAGE6-1-PRE-EXECUTION-FREEZE-002`; no manual baseline execution had begun and no oracle value, protocol rule, mapping, scenario, metric, or worksheet field changed.
- Split Ruff lint, Ruff formatting, Mypy, Codespell, and Yamllint into separately named GitHub Actions steps so a failure identifies the exact gate immediately.
- Recorded the missed YAML-quality gate as BUG-021 and documented the corrective decision in ADR-020.
- Added a Stage 6.1.4 immutable-reference Colab checkpoint and corresponding version, workflow, and checkpoint regression assertions.
- Preserved EvidencePack v0.2, the 34-field EC denominator, all seven locked metrics, and the Stage 6.1 manuscript-eligibility boundary.

## 0.6.1.3 — Stage 6.1.3 final formatter and checkpoint-metadata correction — 2026-07-29

- Applied the final Ruff formatter change to `tests/test_stage6_1_notebook.py`, adding the required top-level definition spacing and removing the excess trailing blank line.
- Recorded the post-packaging formatter regression as BUG-019.
- Corrected the Stage 6.1.2 Colab checkpoint report field from `stage: 6.1.1` to `stage: 6.1.2` and recorded the metadata defect as BUG-020.
- Added a Stage 6.1.3 immutable-reference Colab checkpoint with internally consistent stage and package metadata.
- Added regression assertions for the Stage 6.1.2 and Stage 6.1.3 checkpoint stage fields.
- Required the full-repository `ruff format --check .` gate to run only after all version, notebook, test, manifest, and governance edits are complete.
- Preserved the Stage 6.1 protocol, freeze hashes, independent oracles, fairness mappings, EvidencePack v0.2, the 34-field EC denominator, and all locked metrics unchanged.

## 0.6.1.2 — Stage 6.1.2 Ruff-format correction — 2026-07-29

- Applied the repository-declared Ruff formatter output to all 13 files reported by the Stage 6.1.1 GitHub quality gate.
- Recorded the missed formatter gate as BUG-018 and documented the packaging-process correction in ADR-018.
- Preserved the Stage 6.1 protocol, independent oracles, mappings, worksheet schema, freeze hashes, locked metrics, EvidencePack v0.2, and research outputs unchanged.
- Incremented the corrective checkpoint to Stage 6.1.2 / package v0.6.1.2.
- Added a Stage 6.1.2 immutable-reference Colab checkpoint while preserving the Stage 6.1 and Stage 6.1.1 notebooks as history.
- Required packaging evidence to include both `ruff check .` and `ruff format --check .`; a successful lint pass alone is insufficient.

## 0.6.1.1 — Stage 6.1.1 quality-gate correction — 2026-07-29

- Corrected five Ruff `E702` violations in `tests/stage6_1_helpers.py` by separating CSV header and row writes into individual statements.
- Corrected two Ruff `I001` import-order violations in the Stage 6.1 manual-results and worksheet tests.
- Recorded the CI-only formatting defect as BUG-017.
- Preserved all Stage 6.1 protocols, ADRs, oracles, schemas, metrics, fixture values, test semantics, and research outputs unchanged.
- Incremented the corrective checkpoint to Stage 6.1.1 / package v0.6.1.1 in accordance with the established staged-correction workflow.
- Added ADR-017 and a version-consistency regression test so future corrective packages cannot retain the superseded release number.
- Added a fail-closed quality-environment bootstrap that installs `.[dev]`, verifies Ruff, Mypy, Codespell, Yamllint, and Hypothesis, and records `TOOLCHAIN_NOT_PROVISIONED` when package retrieval is unavailable.
- Added a Stage 6.1.1 immutable-reference Colab checkpoint while preserving the Stage 6.1 notebook as history.

## 0.6.1 — Stage 6.1 matched baseline protocol hardening

- Preserved the Stage 6 deterministic worksheet proxy and ADR-012 as development and ablation history.
- Added a pre-registered manual-assisted baseline protocol with identical scenario releases, ordinary-tool policy, chronology controls, explicit blinding disclosure, and unedited-original preservation.
- Added independent exhaustive state, conflict, and automatic clock-opportunity oracles; conflict precision and recall no longer derive ground truth from either evaluated workflow.
- Added supplemental fairness controls for common-field completeness, partial lineage, equivalent record-bundle generation, and like-for-like source-access accounting while preserving EC, TR, CD, CA, AR, SC, EPG, EvidencePack v0.2, and the 34-field EC denominator.
- Added a structured Excel workbook plus canonical CSV/YAML exchange templates, schema validation, import provenance, source hashes, and manual Time-to-Decision records.
- Added pre-execution hashing for protocols, mappings, oracles, worksheet schema, and all seven scenario files.
- Added ADR-013 through ADR-016, Stage 6.1 reports, tests, packet export, comparison and paper-asset builders, and an exact-reference Colab checkpoint.
- Marked Stage 6.1 as an implementation candidate awaiting real manual execution; no comparison results are generated or manuscript-eligible at this checkpoint.

## 0.6.0 — Stage 6 matched PSIRT baseline comparison

- Added a frozen structured-but-unorchestrated PSIRT worksheet protocol using identical source bytes, release times, validation, and parsers.
- Added generic baseline replay logic without normalized claims, scope-overlap reasoning, numerical orchestration scores, conflict lifecycle, automatic `tau_E` escalation, or EvidencePack generation.
- Added deterministic matched comparison across four primary scenario families and three controls.
- Reported ties in audit reconstructability and seeded-conflict recall rather than designing a uniformly weak baseline.
- Added conflict precision, partial traceability, and a clearly bounded source-review operation proxy as supplemental measures.
- Added Stage 6 figures, tables, run records, protocol provenance, ADR-012, tests, CI replay, release checks, and Colab checkpoint support.
- Preserved EvidencePack Schema v0.2, its 34-field completeness denominator, all prior scenario trajectories, and the historical EPSS online-verification boundary.

## 0.5.7 — Stage 5.5.2 historical EPSS correction

- Corrected the 2024-04-15 CVE-2024-3400 EPSS record from the rejected candidate values `0.95732` / `0.99721` to the dual-source-observed values `0.00371` / `0.72343`.
- Preserved the pinned EPSS v3 model metadata and archive commit while retaining the mandatory online API/archive agreement gate.
- Changed mismatch handling so raw downloads and a diagnostic report containing the observed API, archive and normalized records are preserved before the gate exits non-zero.
- Added root-only ignore rules and repository validation for mutable historical EPSS download artefacts.
- Added regression tests for diagnostic mismatch records and misplaced root downloads.
- Wrapped historical YAML lines that produced quality annotations without changing parsed semantics.
- Recorded the rejected Stage 5.5.1 candidate and accidental root-file commit as BUG-010 and BUG-011.
- Preserved EvidencePack Schema v0.2, its 34-field completeness denominator and all scenario state trajectories.

## 0.5.6 — Stage 5.5.1 historical EPSS verification

- Added fail-closed comparison of the FIRST date-specific EPSS API response and the official daily archive pinned to commit `ca26ecd7b9b806badabd6aedffdc8c4472ce6e85`.
- Added offline verification-contract validation and a mandatory online GitHub quality gate.
- Added preservation of raw API, gzip, extracted-row and verification-report evidence in the Colab checkpoint bundle.
- Reclassified the CVE-2024-3400 historical replay as `PILOT_VERIFICATION_CANDIDATE`; it is eligible for later evaluation freezing only after the online GitHub and Colab gates pass.
- Added a with/without-EPSS ablation showing no state-trajectory or final-`E_t` change in the synthetic reference deployment.
- Added verification and ablation tests, ADR-010, updated evaluation records, paper claims, figures, tables and provenance manifests.
- Corrected the pre-release online eligibility assertion and Colab status oracle to use the final `online_report_hash` and `authoritative_dual_source_verified` fields; registered as BUG-009 before remote execution.
- Preserved EvidencePack Schema v0.2 and its 34-field completeness denominator.

All notable repository design and implementation changes are recorded here.

## [0.2.1] - 2026-07-17

### Fixed on 2026-07-19

- corrected the GitHub Actions references from nonexistent `actions/checkout@v7` and `actions/setup-python@v7` tags to supported `actions/checkout@v6` and `actions/setup-python@v6`;
- added `tests/test_workflow.py` to prevent unsupported action-major drift from recurring.


### Added

- `docs/decision_semantics.md`, freezing the tri-part model for evidential recommendation, configured deadline posture, and EvidencePack construction.
- `docs/decision_records/ADR-001-tri-part-model.md`, recording the DSR refinement from the accepted proposal model.
- `docs/decision_records/ADR-002-semantic-implementation-alignment.md`, recording the corresponding code changes and verification gates.
- `src/sbom_to_audit/model/deadline_engine.py`, implementing configured deadline posture independently of reportability recommendation.
- `src/sbom_to_audit/model/authorization.py`, enforcing explicit human authorization and separate milestone-completion evidence.
- supplemental Execution Latency definitions and benchmarking protocol in `docs/metrics.md`.
- schema-compatible deadline, authorization, and milestone-satisfaction audit-event documentation.
- regression tests for scoring semantics, deadline posture, authorization, schema preservation, and manifest completeness.
- `.github/workflows/tests.yml`, running tests and a deterministic CLI smoke test on Python 3.10, 3.11, and 3.12.

### Changed

- refined the unified proposal model into:
  - `R_t=f(E_t,A_t,I_t,U_t,C_t,delta_t)`;
  - `D_(k,t)=h(delta_t,tau_k,Q_(k,t),S_(k,t))`; and
  - `Pi_t=g(R_t,D_t,M_t,gamma_id,X_t,L_t,H_t,S_t)`.
- corrected `scoring.py` so vulnerable-function execution and reachability contribute to `A_t`, not automatically to `E_t`.
- added active, traceable `malicious_exploitation_observed=true` claims as the only local contributor that may set `E_t=1.0` in v0.2.1.
- retained KEV at `0.85` as vulnerability-level exploitation evidence and EPSS at `0.60 * percentile` as predictive context.
- updated `evidence_pack.py` to pass active claims into scoring.
- rejected missing `gamma_id` rather than inventing identity confidence.
- separated human authorization from milestone completion or submission.
- updated the README, design freeze, scenario protocol, citation metadata, package metadata, and manifest to version 0.2.1.

### Preserved

- EvidencePack Schema version `0.2`.
- all top-level EvidencePack blocks.
- the 34-field Evidence Completeness denominator.
- the locked EC, TR, CD, CA, AR, SC, and EPG equations.
- the allowed recommendation and authorization values.
- conflict precedence and the internal 18-hour Prepare-to-Escalate safeguard.

### Verified

- the full regression suite passes.
- the existing Ghost-Logger EvidencePack remains schema-valid.
- a schema-compatible deadline-status event validates inside `audit_log[]`.
- the deterministic CLI regenerates the EvidencePack, state log, conflict report, and metrics sidecar.
- the final Ghost-Logger state remains `Escalate`; its final `E_t` is now `0.552` rather than the semantically incorrect execution-derived value `1.0`.

### Deferred

- real-format source ingestion and source-hash verification remain Stage 2 work.
- scenario-driven deadline, authorization, and submission events remain Stage 2/3 integration work.
- scoped semantic conflict resolution and event-ledger persistence remain Stage 3 work.

## [0.2.2] - 2026-07-19

### Fixed

- made schema regression tests self-contained by generating their EvidencePack from the committed scenario instead of reading generated outputs excluded by `.gitignore`;
- made manifest validation ignore local virtual environments, analysis caches, and coverage files;
- corrected CI so tests and deterministic smoke replays operate entirely in temporary output directories.

### Added

- pre-commit hooks for Ruff, Mypy, Codespell, Yamllint, and repository validation;
- a separate quality workflow with actionlint v1.7.12, static checks, repository validation, and branch coverage;
- Dependabot monitoring for Python and GitHub Actions dependencies;
- canonical repository and release-validation scripts;
- Hypothesis property tests, parser contract tests, CLI integration tests, evidence-record tests, and repository-integrity tests;
- a 70% branch-coverage ratchet, quality-assurance documentation, known-issues register, bug register, and ADR-003.

### Preserved

- EvidencePack Schema v0.2, the 34 mandatory EC fields, the seven locked effectiveness metrics, the state set, and all v0.2.1 decision semantics.

### Deferred

- immutable SHA pinning for third-party GitHub Actions, mutation testing, full security scanning, strict source-file validation, and Execution Latency instrumentation remain documented follow-up controls.

## [0.2.3] - 2026-07-19

### Added

- a path-confined source registry that computes hashes and records parser, media-type, validation, and file-size evidence;
- committed Ghost-Logger CycloneDX, CSAF/VEX, OSV-shaped, KEV-shaped, EPSS-shaped, telemetry, asset, mitigation, adjudication, authorization, and milestone artefacts;
- a scenario-agnostic real-format ingestion pipeline and scoped conflict engine;
- source-manifest and JSONL audit-ledger outputs;
- full T+2h, T+10h, T+14h, T+20h, and T+72h Ghost-Logger replay;
- strict-source repository validation and source-registry regression tests;
- evaluation run/scenario registries and pilot paper-asset generation;
- ADR-004 and the paper-asset accumulation protocol.

### Changed

- converted `ghost_logger.yaml` from a normalized evidence container into a source-release manifest;
- derived product, identity, vulnerability, supplier, telemetry, asset, and mitigation blocks from committed files;
- separated sequential same-class evidence updates from active cross-class conflicts;
- completed scoped VEX conflict resolution, human authorization, and milestone satisfaction;
- expanded deterministic replay from four to six outputs;
- updated strict repository and release gates for Stage 2 sources;
- corrected deadline lateness so completion exactly at the configured deadline is not labelled late.

### Verified pilot result

- five expected state transitions matched;
- final recommendation: `Report-Ready`;
- final human authorization: `Report`;
- EC, TR, CD, AR, and SC: `1.0`;
- source-integrity, authorization-correctness, and deadline-correctness supplemental checks: `1.0`.

### Limitations

- all Ghost-Logger organisational evidence remains fictional;
- full official CycloneDX/CSAF schema validation, remaining scenarios, public historical replay, matched baseline, mutation testing, and performance evaluation remain pending.

## [0.2.4] - 2026-07-19

### Fixed

- added explicit conflict lifecycle tracking so a historically detected conflict is marked `resolved` when a registered adjudication artefact supersedes a conflicting source;
- added conflict-detection and conflict-resolution audit events with event, timestamp, artefact, rationale, and state lineage;
- prevented inconsistent outputs where final `C_t=false` coexisted with a conflict record still labelled `active`;
- added active and resolved conflict counts to the generated conflict report.

### Added

- a fail-closed invariant requiring final `C_t` to equal the presence of active conflict-history records;
- regression tests covering detection, resolution, lifecycle chronology, audit preservation, and report consistency;
- a pilot conflict-lifecycle table for paper-asset accumulation;
- ADR-005 and BUG-004 documenting the defect, correction, and research impact.

### Preserved

- the intentionally seeded VEX/runtime contradiction at T+10h;
- the five expected state transitions, final `Report-Ready` recommendation, human `Report` authorization, Schema v0.2, and the locked metric definitions.

## [0.3.0] - 2026-07-19

### Added

- canonical claim-scope normalization with product, component, CVE, product-variant, deployment, and environment dimensions;
- scope-relation reasoning for exact, containing, overlapping, and disjoint evidence scopes;
- scope-aware conflict detection that compares contradictory claims when their declared scopes overlap;
- CSAF product-helper extraction of product PURL and model-number variant scope;
- the False Comfort controlled scenario and a scope-matched negative control;
- deterministic multi-scenario release replay across Ghost-Logger, False Comfort, and its negative control;
- Stage 3 pilot comparison figures, tables, run records, and claim-matrix entries;
- ADR-006 documenting scope-aware supplier-assurance applicability.

### Changed

- supplier VEX assertions are retained but are not applied to deployments outside their declared product-variant scope;
- local affectedness claims retain deployment-specific dimensions instead of being widened to product-wide scope;
- CI deterministic smoke tests now execute every committed scenario;
- the release checker now discovers and verifies every scenario and all six outputs per scenario.

### Preserved

- EvidencePack Schema v0.2 and its 34-field Evidence Completeness denominator;
- the tri-part recommendation, deadline, and EvidencePack semantics;
- Ghost-Logger's intentional conflict, its explicit resolution lifecycle, and all Stage 2.0.1 expected states;
- human authorization as distinct from recommendation and milestone satisfaction.

### Pilot interpretation

- False Comfort demonstrates that a valid `known_not_affected` assertion for a standard product variant does not suppress evidence from a disjoint legacy-plugin deployment;
- the negative control confirms that the same assertion is applied when the deployment scope matches and no contradictory local evidence exists;
- these are controlled conformance replays, not industrial validation or legal reportability determinations.

## [0.4.0] - 2026-07-20

### Added

- an offline NVD API 2.0 snapshot parser for target-CVE CVSS base score, severity, and vector context;
- traceable CVSS contextual claims without changing the frozen orchestration equations;
- the Operational Outlier controlled scenario and an exact-source counterfactual lower-impact control;
- Stage 4 pilot comparison figure, temporal replay table, impact-comparison table, run records, and claim-matrix entries;
- ADR-007 documenting the separation of technical severity and operational impact.

### Corrected

- CSAF `under_investigation` is now retained as a supplier-assessment-status claim rather than incorrectly converted into `product_affectedness=false`;
- NVD source validation fails closed when the configured target CVE lacks a usable CVSS metric.

### Preserved

- EvidencePack Schema v0.2 and the 34-field Evidence Completeness denominator;
- the frozen state thresholds and impact equation;
- Ghost-Logger's conflict lifecycle and False Comfort's scope-aware assurance behaviour;
- human authorization and milestone satisfaction as separate events.

### Pilot interpretation

- Operational Outlier and its control share byte-identical non-asset sources, deployment identity, timestamps, deadline profile, CVSS 6.5 MEDIUM, KEV, EPSS, supplier investigation status, and reachability evidence;
- `critical` plus `widespread` context yields `I_t=1.0` and `Report-Ready`, while `medium` plus `limited` yields `I_t=0.5` and `Monitor`;
- the pair demonstrates controlled rule conformance, not external decision accuracy, validated thresholds, or legal reportability.

## [0.5.0] - 2026-07-20

### Added

- Rapid Pivot and a byte-identical early-resolution temporal control;
- evidence-derived unique name/version component resolution and validated CPE-confirmed identity mapping;
- support for unreleased optional EPSS, VEX, and telemetry evidence in intermediate replay snapshots while retaining final Schema v0.2 validation;
- explicit `clock_safeguard_triggered` and `clock_safeguard_hours` state-log and audit properties;
- Clock-Aware Escalation opportunity/trigger counts in the metrics sidecar;
- Stage 5 regression, fail-closed identity, deterministic replay, notebook, and paper-asset tests;
- ADR-008, a Stage 5 report, evaluation summaries, and data-driven Rapid Pivot figure and tables.

### Changed

- generalized CycloneDX identity selection to prefer exact versioned PURL and otherwise require one unique normalized name/version candidate;
- allowed a registered identity-resolution artefact to raise confidence only after validating the selected BOM reference, target PURL, matching method, and CPE evidence;
- generalized snapshot construction so missing optional evidence contributes to the frozen `U_t` equation rather than being fabricated as explicit false values;
- expanded deterministic release replay from five to seven scenarios and from 30 to 42 generated outputs;
- updated package, citation, repository, reproduction, scenario, paper-claim, and known-issues documentation to v0.5.0.

### Preserved

- EvidencePack Schema v0.2 and its 34-field Evidence Completeness denominator;
- all frozen scoring thresholds and the `tau_E=18h` internal safeguard;
- separation of recommendation, human authorization, milestone completion, and workflow-deadline posture;
- Ghost-Logger conflict lifecycle, False Comfort scope reasoning, and Operational Outlier impact differentiation.

### Pilot interpretation

- the main Rapid Pivot replay yields `CA=1.0` from one eligible Prepare-at-18h opportunity and one Escalate transition;
- the early-resolution control has no eligible clock opportunity and retains `CA=null/not_applicable`;
- these are controlled rule-conformance results, not legal, empirical, or industrial validation.


## 0.5.5 — Stage 5.5 public historical replay

- Added a publication-aware CVE-2024-3400 / Operation MidnightEclipse public replay.
- Added fail-closed occurrence-versus-publication temporal leakage checks.
- Added a separate synthetic reference-deployment EvidencePack replay.
- Added `public_exploitation_report` ingestion without conflating public reporting and local telemetry.
- Added historical paper assets, provenance, tests, and deterministic release outputs.
- Marked the historical EPSS value provisional and manuscript-ineligible pending FIRST verification.
- Preserved EvidencePack Schema v0.2 and the 34-field completeness denominator.

### Stage 5.5 pre-release quality correction

- Added referential-integrity validation across evaluation runs, scenarios, and execution environments.
- Added the missing Stage 5.5 local environment record and two historical pilot summaries.
- Regenerated historical source-manifest, EvidencePack, paper-asset, and registry hashes after YAML normalization.
- Registered the omission as `BUG-006`; it was corrected before packaging, GitHub upload, Colab execution, or manuscript eligibility.
- Added the missing `false_comfort_control` scenario-registry row after the new referential-integrity gate exposed the pre-existing omission; registered as `BUG-007` before packaging.
