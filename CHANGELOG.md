# Changelog

All notable repository design and implementation changes are recorded here.

## [0.2.1] - 2026-07-13

### Added

- `docs/decision_semantics.md`, freezing the tri-part model for evidential recommendation, configured deadline posture, and EvidencePack construction.
- `docs/decision_records/ADR-001-tri-part-model.md`, recording the DSR design refinement and its consequences.
- supplemental Execution Latency definitions and benchmarking protocol in `docs/metrics.md`.
- schema-documentation rules for deadline-status, authorization, and milestone-satisfaction audit events.
- revised scenario-oracle requirements separating recommendation, deadline posture, authorization, and submission evidence.

### Changed

- refined the model from `R_t=f(E_t,A_t,I_t,M_t,U_t,C_t,delta_t)` to three functions:
  - `R_t=f(E_t,A_t,I_t,U_t,C_t,delta_t)`;
  - `D_(k,t)=h(delta_t,tau_k,Q_(k,t),S_(k,t))`; and
  - `Pi_t=g(R_t,D_t,M_t,gamma_id,X_t,L_t,H_t,S_t)`.
- clarified that vulnerable-function execution informs applicability `A_t`, not confirmed exploitation `E_t`.
- clarified that `M_t` remains mandatory payload context but is not an independent state-transition input in Prototype semantics v0.2.1.
- clarified that human authorization and milestone completion or submission are separate events.
- updated the drift-control manifest to include all v0.2.1 amendments.

### Preserved

- EvidencePack Schema version `0.2`.
- all top-level EvidencePack blocks.
- the 34-field Evidence Completeness denominator.
- the locked EC, TR, CD, CA, AR, SC, and EPG equations.
- the allowed recommendation and authorization values.

### Not yet implemented

- scoring, state-machine, deadline-engine, ingestion, and scenario-runtime changes required to execute the v0.2.1 semantics. Stage 1 deliberately freezes semantics before those code changes.
