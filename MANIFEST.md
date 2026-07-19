# Repository Manifest

**Schema baseline:** EvidencePack v0.2  
**Semantic baseline:** v0.2.1, approved 2026-07-13  
**Purpose:** Drift control. This file lists every expected scaffold file, its role, creation status, and approved semantic and quality amendments.

**Expected files:** 83  
**Created files:** 83  
**Missing files:** 0

| Path | Purpose | Status |
|---|---|---|
| `README.md` | Project scope, research questions, quick start, non-goals, and repository map. | Amended v0.2.1 |
| `LICENSE` | MIT license for the research code. | Created |
| `CITATION.cff` | Machine-readable software citation metadata. | Amended v0.2.2 |
| `.gitignore` | Excludes environments, quality caches, and generated outputs while retaining placeholders. | Amended v0.2.2 |
| `requirements.txt` | Flat dependency list for simple environments. | Created |
| `pyproject.toml` | Package metadata, bounded dependencies, quality-tool configuration, coverage ratchet, and console entry point. | Amended v0.2.2 |
| `.github/workflows/tests.yml` | Clean-checkout regression on Python 3.10–3.12 with self-contained tests and double-replay comparison. | Amended v0.2.2 |
| `CHANGELOG.md` | Versioned record of semantic, schema, implementation, and evaluation changes. | Created v0.2.1 |
| `docs/design_freeze_v0.2.md` | Locked research questions, tri-part model, scoring semantics, schema, evaluation, and non-claims. | Amended v0.2.1 |
| `docs/decision_semantics.md` | Authoritative definitions of `R_t`, `D_(k,t)`, `Pi_t`, execution/exploitation separation, and authorization/submission boundaries. | Created v0.2.1 |
| `docs/decision_records/ADR-001-tri-part-model.md` | Records the original model, `M_t` inconsistency, approved tri-part refinement, schema decision, and affected modules/tests. | Created v0.2.1 |
| `docs/decision_records/ADR-002-semantic-implementation-alignment.md` | Records the scoring correction, deadline engine, authorization boundary, schema preservation, and regression gates. | Created v0.2.1 |
| `docs/schema.md` | EvidencePack v0.2 fields, mandatory-field rules, and schema-compatible v0.2.1 audit-event extensions. | Amended v0.2.1 |
| `docs/metrics.md` | Frozen effectiveness metrics plus supplemental Execution Latency and scale-benchmark protocol. | Amended v0.2.1 |
| `docs/reproduction.md` | Local and Colab reproduction instructions. | Created |
| `docs/scenario_protocol.md` | Real-format controlled-replay protocol with separate state, deadline, authorization, and submission oracles. | Amended v0.2.1 |
| `schemas/evidencepack_v0.2.schema.json` | JSON Schema for EvidencePack v0.2. | Created |
| `data/README.md` | Data-directory governance and snapshot rules. | Created |
| `data/scenarios/ghost_logger.yaml` | Initial controlled fictional replay with one seeded conflict. | Created |
| `outputs/README.md` | Generated-output directory contract. | Created |
| `notebooks/README.md` | Rules for thin, reproducible Colab notebooks. | Created |
| `src/sbom_to_audit/__init__.py` | Package version and identity. | Amended v0.2.1 |
| `src/sbom_to_audit/utils/__init__.py` | Utility package marker. | Created |
| `src/sbom_to_audit/utils/hashing.py` | SHA-256 helpers. | Created |
| `src/sbom_to_audit/utils/time.py` | UTC parsing and delta_t calculation. | Created |
| `src/sbom_to_audit/utils/io.py` | Deterministic JSON, YAML, and CSV I/O. | Created |
| `src/sbom_to_audit/parsers/__init__.py` | Parser package marker. | Created |
| `src/sbom_to_audit/parsers/cyclonedx_parser.py` | CycloneDX JSON component extraction. | Created |
| `src/sbom_to_audit/parsers/csaf_parser.py` | CSAF/VEX vulnerability and product-status extraction. | Created |
| `src/sbom_to_audit/parsers/osv_client.py` | OSV package/PURL query and CVE-alias extraction. | Created |
| `src/sbom_to_audit/parsers/kev_client.py` | CISA KEV download/snapshot and CVE lookup. | Created |
| `src/sbom_to_audit/parsers/epss_client.py` | FIRST EPSS query, snapshot, and percentile extraction. | Created |
| `src/sbom_to_audit/parsers/telemetry_parser.py` | JSON, JSONL, and CSV telemetry ingestion. | Created |
| `src/sbom_to_audit/parsers/asset_context_parser.py` | JSON/YAML asset-context ingestion. | Created |
| `src/sbom_to_audit/model/__init__.py` | Model package marker. | Amended v0.2.1 |
| `src/sbom_to_audit/model/identity.py` | Locked gamma_id table and uncertainty penalty. | Created |
| `src/sbom_to_audit/model/evidence_record.py` | Typed source-artifact and claim records. | Created |
| `src/sbom_to_audit/model/scoring.py` | v0.2.1 E/A/I/M/U computation with execution/exploitation separation. | Amended v0.2.1 |
| `src/sbom_to_audit/model/state_machine.py` | Frozen state precedence and authorization boundary. | Created |
| `src/sbom_to_audit/model/deadline_engine.py` | Configured reporting-deadline posture independent of recommended state. | Created v0.2.1 |
| `src/sbom_to_audit/model/authorization.py` | Explicit human authorization and separate milestone-satisfaction evidence. | Created v0.2.1 |
| `src/sbom_to_audit/model/metrics.py` | EC, TR, CD, CA, AR, SC, and EPG implementations. | Created |
| `src/sbom_to_audit/model/evidence_pack.py` | Replay, active-claim scoring, conflict detection, audit log, and pack construction. | Amended v0.2.1 |
| `src/sbom_to_audit/cli.py` | Executable replay, schema validation, output, and metrics pipeline. | Created |
| `tests/test_identity.py` | Identity-confidence and uncertainty tests. | Created |
| `tests/test_metrics.py` | Mandatory-field, false-value, EC, and TR tests. | Created |
| `tests/test_scoring.py` | Regression tests for execution, exploitation, KEV, EPSS, missingness, and applicability. | Amended v0.2.1 |
| `tests/test_state_machine.py` | State-rule precedence and mitigation-non-suppression tests. | Amended v0.2.1 |
| `tests/test_deadline_engine.py` | Configured deadline-status precedence and audit-event tests. | Created v0.2.1 |
| `tests/test_authorization.py` | Human authorization and submission-separation tests. | Created v0.2.1 |
| `tests/test_schema.py` | Self-contained EvidencePack v0.2 and deadline-event schema-regression tests. | Amended v0.2.2 |
| `tests/test_manifest.py` | Manifest completeness test resilient to local environments and quality caches. | Amended v0.2.2 |
| `tests/test_workflow.py` | Prevents action-tag drift and verifies independent regression and quality workflows. | Amended v0.2.2 |
| `data/sbom/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/csaf/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/osv_snapshots/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/nvd_snapshots/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/kev_snapshots/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/epss_snapshots/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/telemetry/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/asset_context/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `data/mitigation/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `outputs/evidence_packs/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `outputs/state_logs/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `outputs/conflict_reports/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `outputs/metrics/.gitkeep` | Keeps the required empty directory in Git. | Created |
| `.pre-commit-config.yaml` | Local fail-fast hooks for lint, formatting, typing, spelling, YAML, and repository integrity. | Created v0.2.2 |
| `.yamllint.yml` | YAML style and structural lint configuration. | Created v0.2.2 |
| `.codespellrc` | Typographical-check configuration and repository exclusions. | Created v0.2.2 |
| `.github/dependabot.yml` | Weekly dependency and GitHub Actions update monitoring. | Created v0.2.2 |
| `.github/workflows/quality.yml` | Static analysis, actionlint, repository validation, and coverage quality gate. | Created v0.2.2 |
| `docs/quality_assurance.md` | Defence-in-depth quality controls, fail-closed rules, and coverage policy. | Created v0.2.2 |
| `docs/known_issues.md` | Open limitations and deferred safeguards with risk treatment. | Created v0.2.2 |
| `docs/bug_register.csv` | Structured defect register with root causes, fixes, and regression controls. | Created v0.2.2 |
| `docs/decision_records/ADR-003-quality-gates-and-clean-checkout-tests.md` | Records clean-checkout independence and the Stage 1.5.2 quality-gate decision. | Created v0.2.2 |
| `scripts/validate_repository.py` | Canonical schema, manifest, scenario, and text-integrity validator. | Created v0.2.2 |
| `scripts/release_check.py` | Canonical pre-release quality and deterministic-replay runner. | Created v0.2.2 |
| `tests/test_cli_integration.py` | Clean temporary-output CLI integration and determinism tests. | Created v0.2.2 |
| `tests/test_repository_integrity.py` | Repository-validator and ignore-policy regression tests. | Created v0.2.2 |
| `tests/test_properties.py` | Hypothesis invariants for identity uncertainty and conflict precedence. | Created v0.2.2 |
| `tests/test_parsers.py` | Current parser and offline snapshot helper contract tests. | Created v0.2.2 |
| `tests/test_evidence_record.py` | Typed source-artifact and claim serialization tests. | Created v0.2.2 |
| `MANIFEST.md` | Drift-control inventory of expected files and creation status. | Created |


## v0.2.1 semantic-amendment register

| Amendment | Repository effect | Schema effect | Status |
|---|---|---|---|
| Separate `R_t`, `D_(k,t)`, and `Pi_t` | Added authoritative semantics, deadline engine, authorization boundary, and active-claim scoring. | None | Implemented for Stage 1.5 |
| Remove `M_t` from evidential recommendation | `M_t` remains computed and serialized as mandatory payload context. | None | Approved |
| Separate execution from exploitation | Vulnerable-function execution belongs to `A_t`; active traceable malicious-exploitation claims, KEV, and EPSS contribute to `E_t`. | None | Implemented and tested |
| Separate authorization from submission | Human authorization affects `authorized_state`; milestone satisfaction requires completion or submission evidence. | None | Implemented and tested |
| Add configured deadline posture | Deadline changes are represented as compliant `audit_log[]` events and sidecar summaries. | None | Engine implemented and tested |
| Add Execution Latency | EL is supplemental and stored in metrics or benchmark sidecars. | None | Approved; instrumentation pending |
| Preserve current schema | Top-level blocks, mandatory fields, allowed states, and EC denominator remain unchanged. | EvidencePack remains v0.2 | Verified |

## Stage 1.5 acceptance-gate status

- `scoring.py` implements the v0.2.1 execution/exploitation distinction.
- vulnerable-function execution and confirmed reachability affect `A_t`, not automatically `E_t`.
- active, traceable malicious-exploitation claims, KEV, and EPSS provide graded `E_t` inputs.
- configured deadline posture is calculated independently by `deadline_engine.py`.
- only explicit human events may set `authorized_state`; completion or submission evidence is separate.
- deadline audit events remain valid within the unchanged EvidencePack v0.2 schema.
- the EC denominator remains exactly 34 fields and EL remains supplemental.
- continuous integration and manifest regression checks are present.
- real-format ingestion has not begun and remains blocked until this checkpoint is merged and reproduced.

## Locked checks

- EvidencePack schema version remains `0.2`.
- The EC denominator remains exactly 34 mandatory fields.
- `claims`, `source_artifacts`, `identity_resolution`, `authorized_state`, `audit_log`, `gamma_id`, `delta_t_hours`, and `C_t` are present.
- The first scenario contains one predeclared conflict and expects final state `Escalate`.
- No controlled scenario is described as an industrial case study.
- No component claims to make a legal reporting decision.
