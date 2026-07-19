# Changelog

All notable repository design and implementation changes are recorded here.

## [0.2.1] - 2026-07-17

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
