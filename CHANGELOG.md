# Changelog

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
