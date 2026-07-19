# Decision Semantics (v0.2.1)

**Status:** Approved semantic freeze  
**Applies to:** EvidencePack Schema v0.2 and Prototype semantics v0.2.1  
**Approval date:** 2026-07-13  
**Schema impact:** None. The top-level EvidencePack structure and the 34-field Evidence Completeness denominator remain unchanged.

## 1. Purpose

This document freezes the decision semantics that must be implemented before the real-format ingestion rewrite begins. It separates three operational concerns that were combined in the accepted proposal:

1. evidential recommendation;
2. configured reporting-deadline monitoring; and
3. evidence-payload and audit-snapshot construction.

The prototype is an evidence-orchestration and decision-support artefact. It does not determine legal applicability, establish the legally operative moment of awareness, authorize a regulatory submission, or submit a report.

## 2. Core tri-part architecture

### 2.1 Evidential recommendation

\[
\boxed{R_t=f(E_t,A_t,I_t,U_t,C_t,\Delta t)}
\]

`R_t` is the internal reportability posture recommended from the evidence available at time `t`.

The automatic recommendation logic uses the following precedence order:

\[
R_t =
\begin{cases}
\text{Escalate}, & C_t=\mathrm{true},\\
\text{Escalate}, & R_{t-1}=\text{Prepare}\land \Delta t\geq\tau_E,\\
\text{Report-Ready}, & A_t\geq\theta_A\land E_t\geq\theta_E\land I_t\geq\theta_I,\\
\text{Prepare}, & U_t\geq\theta_U\land(E_t\geq\theta_E\lor I_t\geq\theta_I),\\
\text{Document No-Report}, & A_t\leq\theta_N\land U_t\leq\theta_L,\\
\text{Monitor}, & \text{otherwise.}
\end{cases}
\]

The frozen prototype constants remain:

| Constant | Value | Meaning |
|---|---:|---|
| `tau_E` | 18 hours | Configurable internal Prepare-to-Escalate safeguard; not a statutory deadline. |
| `theta_A` | 0.70 | Applicability threshold. |
| `theta_E` | 0.70 | Exploitation-evidence threshold. |
| `theta_I` | 0.70 | Operational-impact threshold. |
| `theta_U` | 0.50 | Uncertainty threshold. |
| `theta_N` | 0.20 | Low-applicability threshold. |
| `theta_L` | 0.20 | Low-uncertainty threshold. |

The allowed serialized `recommended_state` values remain `Monitor`, `Prepare`, `Escalate`, `Report-Ready`, `Report`, and `Document No-Report`. The automatic function `f` does not originate `Report`; that value is retained for schema compatibility and historical or human-authorized records.

### 2.2 Configured reporting-deadline posture

\[
\boxed{D_{k,t}=h(\Delta t,\tau_k,Q_{k,t},S_{k,t})}
\]

`D_{k,t}` is the configured workflow-deadline posture for milestone `k` at time `t`.

- `delta_t` is elapsed time from the recorded internal awareness proxy.
- `tau_k` is the configured due time for milestone `k`.
- `Q_{k,t}` is a profile-enable flag indicating that milestone `k` is being monitored in the selected replay or organisational workflow profile. It is not a legal determination that a statutory obligation applies.
- `S_{k,t}` is valid evidence that milestone `k` was completed or submitted.

The allowed deadline statuses are:

\[
D_{k,t}\in\{
\text{Not Applicable},
\text{On Track},
\text{Due Soon},
\text{Breach Imminent},
\text{Satisfied},
\text{Overdue}
\}.
\]

Each configured milestone also defines a due-soon lead `w_k` and a breach-imminent lead `b_k`, with:

\[
0 < b_k < w_k < \tau_k.
\]

The status precedence is:

1. `Not Applicable` when `Q_(k,t)` is false;
2. `Satisfied` when valid `S_(k,t)` exists;
3. `Overdue` when `delta_t >= tau_k` and no valid satisfaction evidence exists;
4. `Breach Imminent` when `delta_t >= tau_k - b_k`;
5. `Due Soon` when `delta_t >= tau_k - w_k`;
6. `On Track` otherwise.

When a milestone is satisfied after its configured due time, the current status may become `Satisfied`, but the append-only audit history must preserve the prior `Overdue` event and record whether satisfaction was on time or late.

Configured 24-hour or 72-hour checkpoints are workflow-profile parameters. The prototype does not determine whether those checkpoints legally apply to a particular organisation, product, vulnerability, or incident.

### 2.3 Evidence payload and audit snapshot

\[
\boxed{\Pi_t=g(R_t,D_t,M_t,\gamma_{\mathrm{id}},X_t,L_t,H_t,S_t)}
\]

where:

\[
D_t=\{D_{1,t},D_{2,t},\ldots,D_{n,t}\}
\]

and:

\[
S_t=\{S_{1,t},S_{2,t},\ldots,S_{n,t}\}.
\]

`Pi_t` is the versioned EvidencePack and audit snapshot assembled at time `t`.

- `M_t` is mitigation and remediation status.
- `gamma_id` is identity confidence.
- `X_t` is the underlying asset and deployment context used to derive `I_t`.
- `L_t` is evidence lineage, including claims, source artefacts, hashes, and derivation records.
- `H_t` is the set of explicit human review and authorization events.
- `S_t` is the set of milestone-completion or submission-evidence records.

Historical immutability is not assumed merely because JSON was generated. It is supported through append-only audit events, computed source hashes, deterministic output generation, and preservation of prior pack versions.

## 3. Variable semantics

### 3.1 Exploitation evidence `E_t`

`E_t` represents the strength of exploitation-related evidence. It must not be conflated with component presence, reachability, or vulnerable-function execution.

For Prototype semantics v0.2.1, `E_t` is the maximum of the following computable contributors:

- `1.00` when an active, traceable local or PSIRT claim states `malicious_exploitation_observed=true` for the relevant product, component, vulnerability, deployment, and time scope;
- `0.85` when the vulnerability is present in the replay's dated CISA KEV snapshot; and
- `0.60 * EPSS_percentile` when a dated EPSS percentile is available.

KEV inclusion is vulnerability-level evidence of exploitation in the wild. It does not independently establish exploitation or applicability within the target product environment. EPSS is predictive context and is not proof of exploitation.

Observed exploit attempts, targeted threat-intelligence claims, and other exploitation-related indicators must be preserved as scoped claims. They do not receive additional numeric weights in v0.2.1 unless a later, explicit versioned decision defines and tests those weights.

### 3.2 Applicability `A_t`

`A_t` represents whether the relevant vulnerability is applicable to the identified product, component, version, configuration, and deployment.

The frozen Prototype v0.2 operationalization remains:

- `1.00` for observed vulnerable-function execution or confirmed reachability;
- `0.80` for an applicable `known_affected` or `affected` VEX/CSAF status;
- `0.60 * gamma_id` for component identity alone;
- `0.10` for `known_not_affected` or `not_affected` when no stronger local signal exists; and
- `0.00` when no applicability evidence exists.

Vulnerable-function execution without malicious indicators contributes to `A_t`, not to confirmed exploitation `E_t`.

### 3.3 Operational impact `I_t`

`I_t` represents operational consequence in the relevant deployment context. Prototype v0.2 computes it as the mean of asset criticality and deployment scope:

- criticality: low `0.25`, medium `0.50`, high `0.75`, critical `1.00`;
- scope: isolated `0.25`, limited `0.50`, broad `0.75`, widespread `1.00`.

The underlying `X_t` context is retained in `Pi_t` so that the aggregate score can be audited.

### 3.4 Mitigation `M_t`

`M_t` is deliberately excluded from `R_t` in semantic version v0.2.1.

During artefact construction, the original proposal model:

\[
R_t=f(E_t,A_t,I_t,M_t,U_t,C_t)
\]

was refined because the frozen state rule calculated `M_t` but did not use it in any transition. Prototype v0.2.1 therefore treats mitigation as mandatory payload and audit context, not as an independent mechanism for suppressing an otherwise supported `Escalate` or `Report-Ready` recommendation.

The existing mitigation scale remains:

- none `0.00`;
- planned `0.25`;
- partial or workaround `0.50`;
- deployed `0.75`;
- verified `1.00`.

Mitigation may inform the rationale, later notification updates, and human review. This prototype behaviour is not a legal conclusion about the effect of mitigation on any reporting obligation.

### 3.5 Uncertainty `U_t`

`U_t` represents the uncertainty operationalized by Prototype v0.2.1. The frozen calculation remains:

```text
U_t = 0.4 * missing_fraction + 0.5 * (1 - gamma_id)
```

The checked evidence fields remain KEV status, EPSS percentile, VEX status, execution observation, reachability, telemetry reference, asset criticality, deployment scope, and mitigation status. The result is clamped to `[0,1]`.

This operationalization covers data missingness and identity uncertainty. Other forms of epistemic uncertainty, including stale evidence and incomplete telemetry coverage, must be represented as claims or limitations until a later versioned scoring extension is approved.

### 3.6 Conflict `C_t`

`C_t` is true when active claims contain materially incompatible assertions whose product, component, vulnerability, deployment, and temporal scopes overlap.

An active conflict has precedence:

\[
C_t=\mathrm{true}\Rightarrow R_t=\text{Escalate}.
\]

The Escalate posture persists until a scoped conflict-resolution event marks the relevant claims as confirmed, rejected, superseded, withdrawn, or scope-limited. Conflict resolution must preserve the prior claims and audit history.

### 3.7 Elapsed time `delta_t`

\[
\Delta t=t-t_0
\]

`t_0` is the recorded internal awareness proxy for the controlled replay. It is not a legal determination of statutory awareness.

Elapsed time has two distinct uses:

- within `R_t`, it is used only by the configurable internal `tau_E=18h` Prepare-to-Escalate safeguard;
- within `D_(k,t)`, it is compared with configured workflow milestones `tau_k`.

## 4. Recommendation, authorization, and submission

These are distinct events:

- `recommended_state` is generated by the artefact from `R_t`;
- `authorized_state` may be set only through an explicit human authorization event in `H_t` and remains limited to `Report`, `Document No-Report`, or `null`;
- a deadline milestone becomes `Satisfied` only when valid completion or submission evidence exists in `S_(k,t)`.

Human authorization does not prove submission. Submission evidence does not retroactively erase a late or overdue audit event.

## 5. Schema-preservation rule

EvidencePack Schema v0.2 remains structurally unchanged.

- Deadline-status changes are stored as schema-compatible entries within `audit_log[]`.
- Execution Latency is stored in the metrics sidecar, not as a new mandatory EvidencePack field.
- The Evidence Completeness denominator remains exactly 34 fields.
- Any new required top-level block or mandatory schema field requires EvidencePack v0.3.

## 6. Implementation boundary

This document freezes semantics only. Stage 1 does not change `scoring.py`, `state_machine.py`, or the ingestion pipeline. Those modules must be synchronized with this document under controlled implementation work before final evaluation outputs are generated.
