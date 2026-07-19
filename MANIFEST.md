# Repository Manifest

**EvidencePack schema baseline:** v0.2  
**Semantic baseline:** v0.2.1  
**Implementation baseline:** Stage 2 pilot, package v0.2.3  
**Purpose:** Drift control. Every tracked repository artefact is listed below.

**Expected files:** 133  
**Created files:** 133  
**Missing files:** 0

| Path | Purpose | Status |
|---|---|---|
| `.codespellrc` | Spelling-check configuration. | Preserved |
| `.github/dependabot.yml` | Dependency and GitHub Actions update monitoring. | Preserved |
| `.github/workflows/quality.yml` | Static analysis, strict source validation, and coverage workflow. | Amended v0.2.3 |
| `.github/workflows/tests.yml` | Cross-version regression and deterministic replay workflow. | Preserved |
| `.gitignore` | Excludes local environments, caches, and generated outputs. | Amended v0.2.3 |
| `.pre-commit-config.yaml` | Local fail-fast quality hooks. | Amended v0.2.3 |
| `.yamllint.yml` | YAML lint configuration. | Preserved |
| `CHANGELOG.md` | Versioned semantic, implementation, quality, and evaluation change record. | Amended v0.2.3 |
| `CITATION.cff` | Machine-readable software citation metadata. | Amended v0.2.3 |
| `LICENSE` | MIT licence for the research code. | Preserved |
| `MANIFEST.md` | Drift-control inventory of all tracked repository artefacts. | Preserved |
| `README.md` | Project scope, Stage 2 status, quick start, boundaries, and repository map. | Amended v0.2.3 |
| `data/README.md` | Data governance documentation or required placeholder. | Amended v0.2.3 |
| `data/asset_context/.gitkeep` | Controlled asset-context source or directory placeholder. | Preserved |
| `data/asset_context/ghost_logger_asset.yaml` | Controlled asset-context source or directory placeholder. | Created v0.2.3 |
| `data/csaf/.gitkeep` | CSAF/VEX source artefact or directory placeholder. | Preserved |
| `data/csaf/ghost_logger_vex.json` | CSAF/VEX source artefact or directory placeholder. | Created v0.2.3 |
| `data/decision_records/ghost_logger_authorization.yaml` | Controlled adjudication, authorization, or milestone evidence record. | Created v0.2.3 |
| `data/decision_records/ghost_logger_conflict_resolution.yaml` | Controlled adjudication, authorization, or milestone evidence record. | Created v0.2.3 |
| `data/decision_records/ghost_logger_early_warning_submission.yaml` | Controlled adjudication, authorization, or milestone evidence record. | Created v0.2.3 |
| `data/decision_records/ghost_logger_full_notification_submission.yaml` | Controlled adjudication, authorization, or milestone evidence record. | Created v0.2.3 |
| `data/epss_snapshots/.gitkeep` | Frozen EPSS-shaped source snapshot or directory placeholder. | Preserved |
| `data/epss_snapshots/ghost_logger_epss.json` | Frozen EPSS-shaped source snapshot or directory placeholder. | Created v0.2.3 |
| `data/kev_snapshots/.gitkeep` | Frozen KEV-shaped source snapshot or directory placeholder. | Preserved |
| `data/kev_snapshots/ghost_logger_kev.json` | Frozen KEV-shaped source snapshot or directory placeholder. | Created v0.2.3 |
| `data/mitigation/.gitkeep` | Controlled mitigation source or directory placeholder. | Preserved |
| `data/mitigation/ghost_logger_initial.yaml` | Controlled mitigation source or directory placeholder. | Created v0.2.3 |
| `data/mitigation/ghost_logger_verified.yaml` | Controlled mitigation source or directory placeholder. | Created v0.2.3 |
| `data/nvd_snapshots/.gitkeep` | Data governance documentation or required placeholder. | Preserved |
| `data/osv_snapshots/.gitkeep` | Frozen OSV-shaped source snapshot or directory placeholder. | Preserved |
| `data/osv_snapshots/ghost_logger_osv.json` | Frozen OSV-shaped source snapshot or directory placeholder. | Created v0.2.3 |
| `data/sbom/.gitkeep` | CycloneDX source artefact or directory placeholder. | Preserved |
| `data/sbom/ghost_logger.cdx.json` | CycloneDX source artefact or directory placeholder. | Created v0.2.3 |
| `data/scenarios/ghost_logger.yaml` | Source-release scenario manifest with frozen expected oracles. | Amended v0.2.3 |
| `data/telemetry/.gitkeep` | Controlled runtime telemetry source or directory placeholder. | Preserved |
| `data/telemetry/ghost_logger_execution.jsonl` | Controlled runtime telemetry source or directory placeholder. | Created v0.2.3 |
| `data/telemetry/ghost_logger_initial.jsonl` | Controlled runtime telemetry source or directory placeholder. | Created v0.2.3 |
| `data/telemetry/ghost_logger_reproduction.jsonl` | Controlled runtime telemetry source or directory placeholder. | Created v0.2.3 |
| `docs/bug_register.csv` | Research design, evaluation, quality, reproduction, or governance documentation. | Amended v0.2.3 |
| `docs/decision_records/ADR-001-tri-part-model.md` | Architectural decision record preserving design rationale and consequences. | Preserved |
| `docs/decision_records/ADR-002-semantic-implementation-alignment.md` | Architectural decision record preserving design rationale and consequences. | Preserved |
| `docs/decision_records/ADR-003-quality-gates-and-clean-checkout-tests.md` | Architectural decision record preserving design rationale and consequences. | Preserved |
| `docs/decision_records/ADR-004-real-format-ghost-logger-vertical-slice.md` | Architectural decision record preserving design rationale and consequences. | Created v0.2.3 |
| `docs/decision_semantics.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Preserved |
| `docs/design_freeze_v0.2.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Preserved |
| `docs/known_issues.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Amended v0.2.3 |
| `docs/metrics.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Preserved |
| `docs/paper_asset_protocol.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Created v0.2.3 |
| `docs/paper_claim_matrix.md` | Traceability matrix linking provisional manuscript claims to runs, outputs, and limitations. | Created v0.2.3 |
| `docs/quality_assurance.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Preserved |
| `docs/reproduction.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Amended v0.2.3 |
| `docs/scenario_protocol.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Amended v0.2.3 |
| `docs/schema.md` | Research design, evaluation, quality, reproduction, or governance documentation. | Preserved |
| `docs/stage2_vertical_slice_report.md` | Pilot implementation, validation, result, and limitation report for Stage 2. | Created v0.2.3 |
| `evaluation/README.md` | Research run or scenario registry and evaluation governance. | Created v0.2.3 |
| `evaluation/environments/README.md` | Evaluation environment record or environment-record guidance. | Created v0.2.3 |
| `evaluation/environments/stage2_local_build.json` | Evaluation environment record or environment-record guidance. | Created v0.2.3 |
| `evaluation/run_registry.csv` | Research run or scenario registry and evaluation governance. | Created v0.2.3 |
| `evaluation/scenario_registry.csv` | Research run or scenario registry and evaluation governance. | Created v0.2.3 |
| `evaluation/summaries/README.md` | Derived pilot evaluation summary or summary guidance. | Created v0.2.3 |
| `evaluation/summaries/ghost_logger_stage2_pilot.json` | Derived pilot evaluation summary or summary guidance. | Created v0.2.3 |
| `notebooks/README.md` | Thin Colab notebook rules and Stage 2 checkpoint guidance. | Amended v0.2.3 |
| `notebooks/stage2_colab_checkpoint.ipynb` | Thin clean-room Stage 2 orchestration notebook; no model logic. | Created v0.2.3 |
| `outputs/README.md` | Keeps a generated-output directory present in Git. | Amended v0.2.3 |
| `outputs/audit_ledgers/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/conflict_reports/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/evidence_packs/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/metrics/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/source_manifests/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/state_logs/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `outputs/validation/.gitkeep` | Keeps a generated-output directory present in Git. | Preserved |
| `paper_assets/README.md` | Paper-asset governance, register, or package marker. | Created v0.2.3 |
| `paper_assets/__init__.py` | Paper-asset governance, register, or package marker. | Created v0.2.3 |
| `paper_assets/data/stage2_ghost_logger_asset_manifest.json` | Machine-readable paper-asset provenance manifest. | Created v0.2.3 |
| `paper_assets/figure_table_register.csv` | Paper-asset governance, register, or package marker. | Created v0.2.3 |
| `paper_assets/figures/ghost_logger_trajectory.svg` | Pilot vector figure generated from registered outputs. | Created v0.2.3 |
| `paper_assets/figures/prototype_architecture.svg` | Pilot vector figure generated from registered outputs. | Created v0.2.3 |
| `paper_assets/scripts/__init__.py` | Data-driven paper-asset generation code. | Created v0.2.3 |
| `paper_assets/scripts/build_stage2_assets.py` | Data-driven paper-asset generation code. | Created v0.2.3 |
| `paper_assets/tables/ghost_logger_event_replay.csv` | Pilot tabular paper asset generated from registered outputs. | Created v0.2.3 |
| `paper_assets/tables/ghost_logger_source_inventory.csv` | Pilot tabular paper asset generated from registered outputs. | Created v0.2.3 |
| `pyproject.toml` | Package metadata, dependencies, quality tools, coverage, and entry points. | Amended v0.2.3 |
| `requirements.txt` | Flat runtime dependency list. | Preserved |
| `schemas/evidencepack_v0.2.schema.json` | Locked EvidencePack v0.2 JSON Schema. | Preserved |
| `scripts/release_check.py` | Canonical repository validation or release-quality script. | Amended v0.2.3 |
| `scripts/validate_repository.py` | Canonical repository validation or release-quality script. | Amended v0.2.3 |
| `src/sbom_to_audit/__init__.py` | Package identity or command-line implementation. | Amended v0.2.3 |
| `src/sbom_to_audit/cli.py` | Package identity or command-line implementation. | Amended v0.2.3 |
| `src/sbom_to_audit/ingestion/__init__.py` | Real-format source registration, validation, or ingestion pipeline module. | Created v0.2.3 |
| `src/sbom_to_audit/ingestion/artifact_validator.py` | Real-format source registration, validation, or ingestion pipeline module. | Created v0.2.3 |
| `src/sbom_to_audit/ingestion/ingestion_result.py` | Real-format source registration, validation, or ingestion pipeline module. | Created v0.2.3 |
| `src/sbom_to_audit/ingestion/pipeline.py` | Real-format source registration, validation, or ingestion pipeline module. | Created v0.2.3 |
| `src/sbom_to_audit/ingestion/source_registry.py` | Real-format source registration, validation, or ingestion pipeline module. | Created v0.2.3 |
| `src/sbom_to_audit/model/__init__.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/authorization.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/conflict_engine.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Created v0.2.3 |
| `src/sbom_to_audit/model/deadline_engine.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Amended v0.2.3 |
| `src/sbom_to_audit/model/evidence_pack.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Amended v0.2.3 |
| `src/sbom_to_audit/model/evidence_record.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/identity.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/metrics.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/scoring.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/model/state_machine.py` | Evidence, scoring, conflict, deadline, authorization, state, pack, or metric model. | Preserved |
| `src/sbom_to_audit/parsers/__init__.py` | Format-specific parser or vulnerability-intelligence client. | Preserved |
| `src/sbom_to_audit/parsers/asset_context_parser.py` | Format-specific parser or vulnerability-intelligence client. | Preserved |
| `src/sbom_to_audit/parsers/csaf_parser.py` | Format-specific parser or vulnerability-intelligence client. | Amended v0.2.3 |
| `src/sbom_to_audit/parsers/cyclonedx_parser.py` | Format-specific parser or vulnerability-intelligence client. | Amended v0.2.3 |
| `src/sbom_to_audit/parsers/epss_client.py` | Format-specific parser or vulnerability-intelligence client. | Preserved |
| `src/sbom_to_audit/parsers/kev_client.py` | Format-specific parser or vulnerability-intelligence client. | Preserved |
| `src/sbom_to_audit/parsers/osv_client.py` | Format-specific parser or vulnerability-intelligence client. | Preserved |
| `src/sbom_to_audit/parsers/telemetry_parser.py` | Format-specific parser or vulnerability-intelligence client. | Amended v0.2.3 |
| `src/sbom_to_audit/utils/__init__.py` | Deterministic I/O, hashing, or time utility. | Preserved |
| `src/sbom_to_audit/utils/hashing.py` | Deterministic I/O, hashing, or time utility. | Preserved |
| `src/sbom_to_audit/utils/io.py` | Deterministic I/O, hashing, or time utility. | Amended v0.2.3 |
| `src/sbom_to_audit/utils/time.py` | Deterministic I/O, hashing, or time utility. | Preserved |
| `tests/test_authorization.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_cli_integration.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Amended v0.2.3 |
| `tests/test_conflict_engine.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Created v0.2.3 |
| `tests/test_deadline_engine.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_evidence_record.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_identity.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_manifest.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Amended v0.2.3 |
| `tests/test_metrics.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_paper_assets.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Created v0.2.3 |
| `tests/test_parsers.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_properties.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_real_format_pipeline.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Created v0.2.3 |
| `tests/test_repository_integrity.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Amended v0.2.3 |
| `tests/test_schema.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_scoring.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_source_registry.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Created v0.2.3 |
| `tests/test_state_machine.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |
| `tests/test_workflow.py` | Automated unit, property, parser, integration, schema, or repository regression test. | Preserved |

## v0.2.1 semantic-amendment register

- The tri-part `R_t`, `D_(k,t)`, and `Pi_t` semantics remain authoritative.
- EvidencePack Schema v0.2, the 34-field EC denominator, and seven locked metrics remain unchanged.

## v0.2.3 Stage 2 register

- Ghost-Logger now derives evidence from committed real-format artefacts.
- Six deterministic output products are generated.
- Pilot evaluation and paper assets are explicitly ineligible for final manuscript claims until regenerated from a tagged commit and independently reproduced.
