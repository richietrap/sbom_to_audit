# ADR-001: Separate Evidential State, Deadline Posture, and Evidence Payload

- **Status:** Accepted
- **Decision date:** 2026-07-13
- **Semantic version:** v0.2.1
- **EvidencePack schema version:** v0.2, unchanged

## Context

The accepted proposal model represented reportability as:

\[
R_t=f(E_t,A_t,I_t,M_t,U_t,C_t)
\]

The implementation design later added elapsed time:

\[
R_t=f(E_t,A_t,I_t,M_t,U_t,C_t,\Delta t).
\]

During the Design Science Research construction phase, two inconsistencies were identified:

1. `M_t` was calculated and serialized but did not influence any branch of the frozen state-transition rule. It was therefore a formal input to `R_t` without an implemented state effect.
2. evidential posture, deadline monitoring, human authorization, and milestone completion risked being represented as one state machine even though they answer different operational questions.

A further semantic error was identified in the initial scoring scaffold: vulnerable-function execution was treated as confirmed exploitation evidence. Execution or reachability supports applicability, but does not by itself prove malicious exploitation.

## Decision

Adopt a tri-part architecture:

\[
R_t=f(E_t,A_t,I_t,U_t,C_t,\Delta t)
\]

\[
D_{k,t}=h(\Delta t,\tau_k,Q_{k,t},S_{k,t})
\]

\[
\Pi_t=g(R_t,D_t,M_t,\gamma_{\mathrm{id}},X_t,L_t,H_t,S_t)
\]

with:

\[
D_t=\{D_{1,t},\ldots,D_{n,t}\}
\]

and:

\[
S_t=\{S_{1,t},\ldots,S_{n,t}\}.
\]

The functions have distinct responsibilities:

- `R_t` produces the evidence-supported internal recommendation.
- `D_(k,t)` monitors configured workflow milestones without making a legal applicability determination.
- `Pi_t` assembles the versioned EvidencePack and audit snapshot, including mitigation, lineage, human decisions, and milestone-completion evidence.

`M_t` remains mandatory EvidencePack context but does not independently suppress an `Escalate` or `Report-Ready` recommendation in Prototype v0.2.1.

Human authorization and submission are distinct. An explicit human event may set `authorized_state`; only valid milestone-completion or submission evidence may mark a deadline milestone `Satisfied`.

## Schema-version decision

EvidencePack Schema v0.2 remains unchanged because the refinement does not add, remove, rename, or change the type of any required top-level block or mandatory field.

- `M_t` remains present in `orchestration_metrics` and `mitigation_context`.
- deadline-status changes are represented as additional properties on otherwise valid `audit_log[]` entries;
- execution-latency results are written to the metrics sidecar;
- the EC denominator remains 34.

A dedicated required `deadline_context` block or a new mandatory field would require EvidencePack v0.3.

## Consequences

### Positive

- removes the dead-input inconsistency around `M_t`;
- separates evidence recommendation from workflow timing;
- preserves the human authorization boundary;
- distinguishes authorization from successful submission;
- prevents vulnerable-function execution from being misrepresented as malicious exploitation;
- retains EvidencePack v0.2 compatibility.

### Costs and limitations

- the existing scoring implementation must be changed in a later stage;
- a deadline engine and schema-compatible audit events must be implemented;
- scenario oracles must contain separate recommended-state, deadline-posture, authorization, and submission expectations;
- the refinement must be described transparently in the paper as a DSR construction outcome.

## Affected implementation modules

The following existing modules are affected by later implementation work but are not modified by this semantic-freeze ADR:

- `src/sbom_to_audit/model/scoring.py`
- `src/sbom_to_audit/model/state_machine.py`
- `src/sbom_to_audit/model/evidence_pack.py`
- `src/sbom_to_audit/model/metrics.py`
- `src/sbom_to_audit/cli.py`

Expected new or separated modules include:

- `src/sbom_to_audit/model/deadline_engine.py`
- `src/sbom_to_audit/model/authorization.py`
- `src/sbom_to_audit/model/event_ledger.py`

## Affected tests

Later implementation must amend or add tests for:

- execution contributing to `A_t` but not automatically to `E_t`;
- malicious-exploitation claims contributing to `E_t`;
- deadline-status precedence;
- authorization versus milestone satisfaction;
- schema-valid deadline audit events;
- preservation of the 34-field EC denominator;
- deterministic scenario oracles containing separate state and deadline expectations.

## Alternatives considered

### Keep `M_t` in `R_t` without using it

Rejected because it preserves a mathematical and implementation inconsistency.

### Add mitigation as a state-suppression rule

Rejected for v0.2.1 because no agreed, validated transition rule exists and mitigation must not silently erase prior exploitation, conflict, or impact evidence.

### Add `Breach-Imminent` to `recommended_state`

Rejected because it is a workflow-clock condition rather than an evidential posture and would alter the locked state enumeration.

### Add a top-level `deadline_context` block

Deferred to a possible EvidencePack v0.3 because it would be a structural schema change.
