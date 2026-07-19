# ADR-002: Align the Prototype Implementation with Semantic Version v0.2.1

- **Status:** Accepted and implemented
- **Decision date:** 2026-07-17
- **Prototype version:** 0.2.1
- **EvidencePack schema version:** 0.2, unchanged
- **Supersedes:** the execution-to-exploitation behaviour in the initial scoring scaffold

## Context

ADR-001 separated evidential recommendation, configured deadline posture, and evidence-payload construction:

\[
R_t=f(E_t,A_t,I_t,U_t,C_t,\Delta t)
\]

\[
D_{k,t}=h(\Delta t,\tau_k,Q_{k,t},S_{k,t})
\]

\[
\Pi_t=g(R_t,D_t,M_t,\gamma_{\mathrm{id}},X_t,L_t,H_t,S_t).
\]

The semantic freeze deliberately preceded code changes. The initial implementation still:

1. assigned `E_t=1.0` when vulnerable-function execution was observed;
2. had no implementation of configured deadline posture;
3. validated authorized-state values but did not provide an explicit human-event boundary; and
4. had no separate representation of milestone-completion or submission evidence.

These behaviours were inconsistent with the approved v0.2.1 semantics and had to be corrected before real-format ingestion.

## Decision

### Exploitation and applicability

`src/sbom_to_audit/model/scoring.py` now treats vulnerable-function execution and confirmed reachability as applicability evidence only. They may set `A_t=1.0` but do not independently raise `E_t`.

`E_t` is the maximum of:

- `1.00` for an active, traceable claim with `proposition=malicious_exploitation_observed` and `value=true`;
- `0.85` for dated CISA KEV inclusion; and
- `0.60 * EPSS_percentile` for dated predictive context.

Missing evidence remains distinct from an explicit negative through the existing `U_t` missingness calculation. Missing identity confidence is rejected rather than invented.

### Configured deadline posture

`src/sbom_to_audit/model/deadline_engine.py` implements `D_(k,t)` independently of `recommended_state`. It supports:

- `Not Applicable`;
- `On Track`;
- `Due Soon`;
- `Breach Imminent`;
- `Satisfied`; and
- `Overdue`.

A deadline becomes `Satisfied` only when a non-empty milestone-completion or submission-evidence identifier is present. Deadline events retain the six base fields required by the unchanged EvidencePack v0.2 `audit_log[]` schema.

### Authorization and submission

`src/sbom_to_audit/model/authorization.py` requires an explicit event with `actor_type=human` to set `authorized_state`. It models milestone-completion or submission evidence separately. Authorization does not mark a deadline milestone `Satisfied`, and milestone satisfaction does not rewrite the evidential recommendation.

### Continuous regression

`.github/workflows/tests.yml` runs the regression suite and deterministic CLI smoke test on Python 3.10, 3.11, and 3.12 for pushes and pull requests.

## Schema and metric decision

EvidencePack Schema v0.2 remains unchanged:

- no top-level block was added;
- no mandatory field was added, removed, or renamed;
- the 34-field EC denominator is unchanged;
- `Breach Imminent` is not a `recommended_state`;
- deadline and authorization details are schema-compatible additional properties on otherwise valid audit events; and
- Execution Latency remains supplemental and is not added to the EvidencePack schema in this stage.

## Files changed

- `src/sbom_to_audit/model/scoring.py`
- `src/sbom_to_audit/model/evidence_pack.py`
- `src/sbom_to_audit/model/deadline_engine.py`
- `src/sbom_to_audit/model/authorization.py`
- `src/sbom_to_audit/__init__.py`
- `pyproject.toml`
- `CITATION.cff`
- `tests/test_scoring.py`
- `tests/test_state_machine.py`
- `tests/test_deadline_engine.py`
- `tests/test_authorization.py`
- `tests/test_schema.py`
- `tests/test_manifest.py`
- `.github/workflows/tests.yml`
- `CHANGELOG.md`
- `MANIFEST.md`

## Verification requirements

The implementation alignment is accepted only when:

- the complete local regression suite passes;
- the existing EvidencePack validates against Schema v0.2;
- a deadline-status audit event validates when appended to that pack;
- the CLI regenerates all four scaffold outputs;
- the final Ghost-Logger state remains `Escalate` because conflict precedence is unchanged;
- the final Ghost-Logger `E_t` falls from the incorrect execution-derived value of `1.0` to the EPSS-derived value of `0.552` in the absence of malicious-exploitation or KEV evidence;
- the manifest reports no missing required files; and
- scoring and deadline results are deterministic across repeated executions.

## Consequences

### Positive

- code and frozen semantics are now consistent;
- execution is no longer misrepresented as exploitation;
- deadline posture is testable without changing the state enumeration;
- authorization and submission are independently auditable;
- schema and metric drift are prevented through regression tests and CI.

### Limitations

- the current Ghost-Logger scenario still supplies normalized evidence and claims through YAML;
- the deadline and authorization modules are validated independently but are not yet driven by real-format scenario events;
- scoped claim compatibility and event-sourced conflict resolution remain Stage 3 work;
- real-format ingestion remains Stage 2 work.
