# Design Freeze v0.2

**Semantic amendment:** v0.2.1, approved 2026-07-13  
**Status:** Locked semantic implementation baseline  
**Repository:** `sbom-to-audit`  
**Python package:** `sbom_to_audit`  
**Machine-readable schema:** EvidencePack v0.2, unchanged

This document prevents silent drift between the paper, schema, implementation, controlled scenarios, and evaluation outputs. The v0.2.1 amendment refines decision semantics without changing the EvidencePack v0.2 structure or the 34-field Evidence Completeness denominator.

## 1. Research questions

The following research questions remain frozen unless an explicit, versioned decision changes them.

**RQ1.** What evidence artifacts are required to support defensible reportability decisions for actively exploited vulnerabilities and severe product-security incidents?

**RQ2.** How can SBOM, VEX/CSAF, CVE, KEV, EPSS, reachability, telemetry, asset-context, and PSIRT records be normalized and linked into an auditable evidence chain?

**RQ3.** How can reportability be operationalized as a temporal state transition with explicit uncertainty, mitigation, impact, identity-confidence, regulatory-clock, and conflict-handling mechanisms?

**RQ4.** Can a proof-of-concept implementation ingest real security-data formats and public vulnerability-intelligence sources to generate auditable evidence packs and state-transition logs?

**RQ5.** To what extent does the implemented artefact improve evidence completeness, traceability, conflict detection, clock-aware escalation, and audit reconstructability compared with an un-orchestrated PSIRT workflow?

## 2. Approved tri-part model

The accepted proposal used:

```text
R_t = f(E_t, A_t, I_t, M_t, U_t, C_t)
```

The v0.2.1 Design Science construction refinement separates evidential posture, configured workflow deadlines, and EvidencePack construction:

```text
R_t     = f(E_t, A_t, I_t, U_t, C_t, delta_t)
D_(k,t) = h(delta_t, tau_k, Q_(k,t), S_(k,t))
Pi_t    = g(R_t, D_t, M_t, gamma_id, X_t, L_t, H_t, S_t)

D_t = {D_(1,t), ..., D_(n,t)}
S_t = {S_(1,t), ..., S_(n,t)}
```

The authoritative definitions are in `docs/decision_semantics.md`; the rationale is recorded in `docs/decision_records/ADR-001-tri-part-model.md`.

### 2.1 Evidential recommendation

`R_t` is evaluated in the following frozen precedence order:

```text
Escalate,           if C_t is true
Escalate,           if R_(t-1) = Prepare and delta_t >= tau_E
Report-Ready,       if A_t >= theta_A and E_t >= theta_E and I_t >= theta_I
Prepare,            if U_t >= theta_U and (E_t >= theta_E or I_t >= theta_I)
Document No-Report, if A_t <= theta_N and U_t <= theta_L
Monitor,            otherwise
```

Prototype constants:

| Constant | Value | Purpose |
|---|---:|---|
| `tau_E` | 18 hours | Internal Prepare-to-Escalate safeguard; not a statutory deadline or legal advice. |
| `theta_A` | 0.70 | Applicability threshold. |
| `theta_E` | 0.70 | Exploitation-evidence threshold. |
| `theta_I` | 0.70 | Operational-impact threshold. |
| `theta_U` | 0.50 | Uncertainty threshold. |
| `theta_N` | 0.20 | Low-applicability threshold. |
| `theta_L` | 0.20 | Low-uncertainty threshold. |

Only a human event may set `authorized_state` to `Report` or `Document No-Report`. The automatic recommendation function does not originate `Report`.

### 2.2 Configured deadline posture

`D_(k,t)` tracks a configured workflow milestone. It does not determine legal applicability or the legally operative moment of awareness.

Allowed deadline statuses:

- `Not Applicable`
- `On Track`
- `Due Soon`
- `Breach Imminent`
- `Satisfied`
- `Overdue`

Deadline status remains distinct from `recommended_state`. It is serialized through schema-compatible audit events and the metrics sidecar rather than a new EvidencePack top-level block.

### 2.3 Evidence payload

`Pi_t` is the versioned EvidencePack and audit snapshot. It preserves mitigation, identity confidence, asset context, lineage, human events, milestone statuses, and satisfaction evidence without assuming that generated JSON is inherently immutable.

## 3. Variable semantics

### 3.1 Exploitation evidence `E_t`

Prototype semantics v0.2.1 separates exploitation from applicability. `E_t` is the maximum of:

- `1.00` for an active, traceable, correctly scoped claim `malicious_exploitation_observed=true`;
- `0.85` when the CVE appears in the replay's dated CISA KEV snapshot; and
- `0.60 * EPSS_percentile` when a dated EPSS percentile is available.

Vulnerable-function execution, package presence, and reachability do not automatically prove exploitation. KEV is vulnerability-level evidence of exploitation in the wild and does not independently establish exploitation or applicability in the target product environment.

Other exploit-attempt or threat-intelligence claims are preserved as evidence but receive no additional numeric weight in v0.2.1 unless an explicit later decision defines and tests that weight.

### 3.2 Applicability `A_t`

`A_t` uses the strongest available local or supplier-supported signal:

- `1.00` for observed vulnerable-function execution or confirmed reachability;
- `0.80` for `known_affected` or `affected` VEX/CSAF status;
- `0.60 * gamma_id` for component identity alone;
- `0.10` for `known_not_affected` or `not_affected` when no stronger local signal exists; and
- `0.00` when no applicability evidence exists.

Local runtime evidence may dominate the applicability score while contradictory supplier and local claims separately set `C_t=true`.

### 3.3 Operational impact `I_t`

`I_t` is the mean of asset criticality and deployment scope:

- criticality: low `0.25`, medium `0.50`, high `0.75`, critical `1.00`;
- scope: isolated `0.25`, limited `0.50`, broad `0.75`, widespread `1.00`.

The underlying asset and deployment evidence is retained as `X_t` within the payload.

### 3.4 Mitigation `M_t`

`M_t` remains calculated and mandatory payload context:

- none `0.00`;
- planned `0.25`;
- partial or workaround `0.50`;
- deployed `0.75`;
- verified `1.00`.

It is excluded from `R_t` because Prototype v0.2.1 does not allow mitigation independently to suppress an otherwise supported `Escalate` or `Report-Ready` recommendation. It may inform rationale, human review, and later notification updates.

### 3.5 Uncertainty `U_t`

The frozen v0.2.1 operationalization is:

```text
U_t = 0.4 * missing_fraction + 0.5 * (1 - gamma_id)
```

The checked fields are KEV status, EPSS percentile, VEX status, execution observation, reachability, telemetry reference, asset criticality, deployment scope, and mitigation status. The result is clamped to `[0,1]`.

This version measures data missingness and identity uncertainty. Other uncertainty dimensions remain explicit claims or limitations unless a later versioned extension is approved.

### 3.6 Conflict `C_t`

A conflict exists when active claims contain materially incompatible assertions with overlapping product, component, vulnerability, deployment, and temporal scope:

```text
C_t = true  =>  R_t = Escalate
```

Escalation persists until a scoped resolution event records how the claims were confirmed, rejected, superseded, withdrawn, or scope-limited. The audit history must be preserved.

### 3.7 Elapsed time `delta_t`

```text
delta_t = t - t_0
```

`t_0` is an internal awareness proxy for controlled evaluation, not a legal determination of statutory awareness.

- `delta_t` affects `R_t` only through the internal `tau_E` safeguard.
- configured reporting checkpoints are evaluated separately through `D_(k,t)`.

## 4. Identity confidence

Identity confidence remains represented as `gamma_id` in `[0,1]`:

| Match type | `gamma_id` |
|---|---:|
| Exact versioned PURL match | 1.0 |
| OSV ecosystem/name/version match | 0.9 |
| Exact CPE with confirmed vendor/product/version | 0.7 |
| Fuzzy name/version match | 0.4 |
| Name-only match | 0.2 |

Identity uncertainty is added as:

```text
U_t <- U_t + lambda_id * (1 - gamma_id)
```

The prototype uses `lambda_id = 0.5` and clamps values to `[0,1]`. OSV is the preferred ecosystem-native bridge from package coordinates or versioned PURLs to vulnerability aliases. The artefact does not claim to solve all PURL/CPE mismatches.

## 5. Recommendation, authorization, and submission

These events are not interchangeable:

- `recommended_state` is generated by `R_t`;
- `authorized_state` requires an explicit human event `H_t`;
- a deadline milestone becomes `Satisfied` only through valid completion or submission evidence `S_(k,t)`.

Authorization does not prove successful submission. Late satisfaction does not erase a prior overdue audit event.

## 6. EvidencePack v0.2

The top-level blocks remain frozen:

```json
{
  "schema_version": "0.2",
  "case_metadata": {},
  "product_context": {},
  "identity_resolution": {},
  "vulnerability_intelligence": {},
  "supplier_assertions": {},
  "local_evidence": {},
  "asset_context": {},
  "mitigation_context": {},
  "orchestration_metrics": {},
  "decision_state": {},
  "claims": [],
  "source_artifacts": [],
  "audit_log": []
}
```

The 34 mandatory Evidence Completeness fields remain defined in `docs/schema.md`. Boolean `false` counts as populated. `authorized_state` remains structurally required but is not a thirty-fifth EC field.

Versioning rule:

- documentation and semantic clarification without structural schema change: `v0.2.1`;
- structural schema change: `v0.3`.

## 7. Evaluation

The locked metrics remain Evidence Completeness, Traceability Ratio, Conflict Detection, Clock-Aware Escalation, Audit Reconstructability, State Correctness, and Evidence-Pack Generation. Their definitions are unchanged in `docs/metrics.md`.

Execution Latency is supplemental and does not alter the locked metric set or EC denominator.

The final evaluation uses four **controlled scenario replays over real-format artifacts**:

1. Silent Transitive / Ghost-Logger;
2. False Comfort;
3. Operational Outlier; and
4. Rapid Pivot.

They are not industrial case studies. Optional expert review is formative unless genuine industrial evaluation is completed.

## 8. Baseline

The baseline is a conventional un-orchestrated PSIRT workflow in which an analyst separately inspects the same evidence and manually records identity links, conflicts, timing, rationale, and provenance.

The analyst may use ordinary, predeclared inspection tools such as `jq`, `grep`, text editors, spreadsheet software, and JSON/CSV viewers. The comparison isolates orchestration, evidence linking, conflict handling, deadline monitoring, and audit construction rather than raw file parsing ability.

## 9. Implementation status at semantic freeze

Stage 1 freezes documentation and governance only. It deliberately does not change `scoring.py`, `state_machine.py`, or the ingestion pipeline. Existing generated Ghost-Logger outputs remain scaffold outputs and must not be used as final v0.2.1 evaluation results.

Implementation must be synchronized with this design before the final scenario replays are generated.

## 10. Non-claims

The artefact does not make legal decisions, determine statutory applicability, establish legal awareness, submit regulatory reports, replace a PSIRT, provide industrial validation by itself, or completely resolve software-identity mismatch.
