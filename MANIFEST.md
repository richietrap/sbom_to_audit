# Repository Manifest

**Schema baseline:** EvidencePack v0.2  
**Semantic baseline:** v0.2.1, approved 2026-07-13  
**Purpose:** Drift control. This file lists every expected scaffold file, its role, creation status, and approved semantic amendments.

**Expected files:** 58  
**Created files:** 58  
**Missing files:** 0

| Path | Purpose | Status |
|---|---|---|
| `README.md` | Project scope, research questions, quick start, non-goals, and repository map. | Created |
| `LICENSE` | MIT license for the research code. | Created |
| `CITATION.cff` | Machine-readable software citation metadata. | Created |
| `.gitignore` | Excludes environments and generated outputs while retaining placeholders. | Created |
| `requirements.txt` | Flat dependency list for simple environments. | Created |
| `pyproject.toml` | Package metadata, dependencies, console entry point, and pytest configuration. | Created |
| `CHANGELOG.md` | Versioned record of semantic, schema, implementation, and evaluation changes. | Created v0.2.1 |
| `docs/design_freeze_v0.2.md` | Locked research questions, tri-part model, scoring semantics, schema, evaluation, and non-claims. | Amended v0.2.1 |
| `docs/decision_semantics.md` | Authoritative definitions of `R_t`, `D_(k,t)`, `Pi_t`, execution/exploitation separation, and authorization/submission boundaries. | Created v0.2.1 |
| `docs/decision_records/ADR-001-tri-part-model.md` | Records the original model, `M_t` inconsistency, approved tri-part refinement, schema decision, and affected modules/tests. | Created v0.2.1 |
| `docs/schema.md` | EvidencePack v0.2 fields, mandatory-field rules, and schema-compatible v0.2.1 audit-event extensions. | Amended v0.2.1 |
| `docs/metrics.md` | Frozen effectiveness metrics plus supplemental Execution Latency and scale-benchmark protocol. | Amended v0.2.1 |
| `docs/reproduction.md` | Local and Colab reproduction instructions. | Created |
| `docs/scenario_protocol.md` | Real-format controlled-replay protocol with separate state, deadline, authorization, and submission oracles. | Amended v0.2.1 |
| `schemas/evidencepack_v0.2.schema.json` | JSON Schema for EvidencePack v0.2. | Created |
| `data/README.md` | Data-directory governance and snapshot rules. | Created |
| `data/scenarios/ghost_logger.yaml` | Initial controlled fictional replay with one seeded conflict. | Created |
| `outputs/README.md` | Generated-output directory contract. | Created |
| `notebooks/README.md` | Rules for thin, reproducible Colab notebooks. | Created |
| `src/sbom_to_audit/__init__.py` | Package version and identity. | Created |
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
| `src/sbom_to_audit/model/__init__.py` | Model package marker. | Created |
| `src/sbom_to_audit/model/identity.py` | Locked gamma_id table and uncertainty penalty. | Created |
| `src/sbom_to_audit/model/evidence_record.py` | Typed source-artifact and claim records. | Created |
| `src/sbom_to_audit/model/scoring.py` | Transparent E/A/I/M/U computation. | Created |
| `src/sbom_to_audit/model/state_machine.py` | Frozen state precedence and authorization boundary. | Created |
| `src/sbom_to_audit/model/metrics.py` | EC, TR, CD, CA, AR, SC, and EPG implementations. | Created |
| `src/sbom_to_audit/model/evidence_pack.py` | Replay, conflict detection, audit log, and pack construction. | Created |
| `src/sbom_to_audit/cli.py` | Executable replay, schema validation, output, and metrics pipeline. | Created |
| `tests/test_identity.py` | Identity-confidence and uncertainty tests. | Created |
| `tests/test_metrics.py` | Mandatory-field, false-value, EC, and TR tests. | Created |
| `tests/test_scoring.py` | Scoring tests for supplier and local evidence. | Created |
| `tests/test_state_machine.py` | State-rule precedence tests. | Created |
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
| `MANIFEST.md` | Drift-control inventory of expected files and creation status. | Created |


## v0.2.1 semantic-amendment register

| Amendment | Repository effect | Schema effect | Status |
|---|---|---|---|
| Separate `R_t`, `D_(k,t)`, and `Pi_t` | Added authoritative semantics and ADR; implementation changes deferred to the next stage. | None | Approved |
| Remove `M_t` from evidential recommendation | `M_t` remains computed and serialized as mandatory payload context. | None | Approved |
| Separate execution from exploitation | Vulnerable-function execution belongs to `A_t`; a scoped malicious-exploitation claim, KEV, and EPSS contribute to `E_t`. | None | Approved; code synchronization pending |
| Separate authorization from submission | Human authorization affects `authorized_state`; milestone satisfaction requires completion or submission evidence. | None | Approved |
| Add configured deadline posture | Deadline changes are represented as compliant `audit_log[]` events and sidecar summaries. | None | Approved; engine pending |
| Add Execution Latency | EL is supplemental and stored in metrics or benchmark sidecars. | None | Approved; instrumentation pending |
| Preserve current schema | Top-level blocks, mandatory fields, allowed states, and EC denominator remain unchanged. | EvidencePack remains v0.2 | Verified |

## Stage 1 acceptance-gate status

- Every model variable has an authoritative definition in `docs/decision_semantics.md`.
- Vulnerable-function execution and malicious exploitation are semantically separated.
- `M_t` treatment is documented as payload context rather than an independent `R_t` input.
- configured deadline posture is distinct from evidential `recommended_state`.
- human authorization is distinct from milestone completion or submission.
- the unchanged JSON Schema validates the existing Ghost-Logger scaffold EvidencePack and a schema-compatible deadline audit event.
- no scoring or state-machine source code was changed during Stage 1.

## Locked checks

- EvidencePack schema version remains `0.2`.
- The EC denominator remains exactly 34 mandatory fields.
- `claims`, `source_artifacts`, `identity_resolution`, `authorized_state`, `audit_log`, `gamma_id`, `delta_t_hours`, and `C_t` are present.
- The first scenario contains one predeclared conflict and expects final state `Escalate`.
- No controlled scenario is described as an industrial case study.
- No component claims to make a legal reporting decision.
