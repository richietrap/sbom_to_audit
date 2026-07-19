# Design Freeze v0.2

**Status:** Locked implementation baseline, amended by semantic version v0.2.1  
**Repository:** `sbom-to-audit`  
**Python package:** `sbom_to_audit`

This document prevents silent drift between the paper, schema, implementation, controlled scenarios, and evaluation outputs.

## 1. Research questions

The following research questions are frozen unless an explicit version decision changes them.

**RQ1.** What evidence artifacts are required to support defensible reportability decisions for actively exploited vulnerabilities and severe product-security incidents?

**RQ2.** How can SBOM, VEX/CSAF, CVE, KEV, EPSS, reachability, telemetry, asset-context, and PSIRT records be normalized and linked into an auditable evidence chain?

**RQ3.** How can reportability be operationalized as a temporal state transition with explicit uncertainty, mitigation, impact, identity-confidence, regulatory-clock, and conflict-handling mechanisms?

**RQ4.** Can a proof-of-concept implementation ingest real security-data formats and public vulnerability-intelligence sources to generate auditable evidence packs and state-transition logs?

**RQ5.** To what extent does the implemented artefact improve evidence completeness, traceability, conflict detection, clock-aware escalation, and audit reconstructability compared with an un-orchestrated PSIRT workflow?

## 2. Tri-part model

During Design Science construction, the accepted proposal's unified equation was refined under ADR-001 and implemented under ADR-002 as:

```text
R_t     = f(E_t, A_t, I_t, U_t, C_t, delta_t)
D_(k,t) = h(delta_t, tau_k, Q_(k,t), S_(k,t))
Pi_t    = g(R_t, D_t, M_t, gamma_id, X_t, L_t, H_t, S_t)
delta_t = t - t_0
```

`R_t` is the evidence-supported internal recommendation. `D_(k,t)` is the configured workflow-deadline posture for milestone `k`. `Pi_t` is the versioned EvidencePack and audit snapshot. `t_0` is an internal awareness proxy and is not a legal determination of statutory awareness.

The state rule is evaluated in the following precedence order:

```text
Escalate,          if C_t is true
Escalate,          if R_(t-1) = Prepare and delta_t >= tau_E
Report-Ready,      if A_t >= theta_A and E_t >= theta_E and I_t >= theta_I
Prepare,           if U_t >= theta_U and (E_t >= theta_E or I_t >= theta_I)
Document No-Report,if A_t <= theta_N and U_t <= theta_L
Monitor,           otherwise
```

Prototype constants:

| Constant | Value | Purpose |
|---|---:|---|
| `tau_E` | 18 hours | Internal PSIRT safeguard before a 24-hour reporting window; not legal advice. |
| `theta_A` | 0.70 | Applicability threshold. |
| `theta_E` | 0.70 | Exploitation-evidence threshold. |
| `theta_I` | 0.70 | Operational-impact threshold. |
| `theta_U` | 0.50 | Uncertainty threshold. |
| `theta_N` | 0.20 | Low-applicability threshold. |
| `theta_L` | 0.20 | Low-uncertainty threshold. |

Only a human may set `authorized_state` to `Report` or `Document No-Report`. The artefact may recommend `Report-Ready`; it never autonomously authorizes a legal submission.

## 3. Conflict handling

A conflict exists when two active evidence claims make incompatible assertions about the same reportability-relevant proposition:

```text
C_t = exists p in P: claim_i(p,t) is incompatible with claim_j(p,t)
C_t = true  =>  R_t = Escalate
```

The initial implementation detects direct value disagreement within a shared proposition. It records the conflicting claim identifiers, values, source references, timestamps, and confidence. More sophisticated semantic conflict resolution is future work.

## 4. Identity confidence

Identity confidence is represented as `gamma_id` in `[0,1]`:

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

The prototype uses `lambda_id = 0.5`. Values are clamped to `[0,1]`. OSV is the preferred ecosystem-native bridge from package coordinates or versioned PURLs to vulnerability aliases, including CVE aliases where available. The artefact does not claim to solve all PURL/CPE mismatches.

## 5. Transparent prototype scoring

The formal state model is locked; these scoring functions are the first transparent operationalization and may be calibrated only through an explicit versioned change.

### Exploitation evidence `E_t`

`E_t` is the maximum of:

- `1.00` when an active, traceable claim records `malicious_exploitation_observed=true`;
- `0.85` when the CVE is in the replay's dated CISA KEV snapshot; and
- `0.60 * EPSS_percentile` when a dated EPSS percentile is available.

Vulnerable-function execution or confirmed reachability does not independently increase `E_t`; it is applicability evidence for `A_t`. KEV is vulnerability-level evidence of exploitation in the wild and does not prove exploitation of the target product environment. EPSS is predictive context rather than proof of exploitation.

### Applicability `A_t`

`A_t` uses the strongest available local or supplier-supported signal:

- `1.00` for observed execution or confirmed reachability;
- `0.80` for `known_affected` / `affected` VEX or CSAF status;
- `0.60 * gamma_id` for component identity alone;
- `0.10` for `known_not_affected` / `not_affected` when no stronger local signal exists; and
- `0.00` when no applicability evidence exists.

Local runtime evidence takes precedence in the score, while contradictory supplier and local claims separately set `C_t=true` and force escalation.

### Impact `I_t`

`I_t` is the mean of asset criticality and deployment scope:

- criticality: low `0.25`, medium `0.50`, high `0.75`, critical `1.00`;
- scope: isolated `0.25`, limited `0.50`, broad `0.75`, widespread `1.00`.

### Mitigation `M_t`

Mitigation status is excluded from the evidential recommendation function `R_t` and retained as mandatory context within `Pi_t`. It does not independently suppress an otherwise supported `Escalate` or `Report-Ready` recommendation:

- none `0.00`;
- planned `0.25`;
- partial / workaround `0.50`;
- deployed `0.75`;
- verified `1.00`.

### Uncertainty `U_t`

The prototype uncertainty score is:

```text
U_t = 0.4 * missing_fraction + 0.5 * (1 - gamma_id)
```

The checked fields are KEV status, EPSS percentile, VEX status, execution observation, reachability, telemetry reference, asset criticality, deployment scope, and mitigation status. The result is clamped to `[0,1]`. Conflict remains separate in `C_t` so the implementation does not hide disagreement inside an aggregate uncertainty value.

## 6. EvidencePack v0.2

The top-level blocks are frozen:

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

The 34 mandatory fields used by Evidence Completeness are defined in `docs/schema.md`. Boolean `false` counts as populated. `authorized_state` is required in the schema even though it is not an additional EC denominator field.

Versioning rule:

- documentation-only clarification: `v0.2.1`;
- structural schema change: `v0.3`.

## 7. Evaluation

The frozen metrics are Evidence Completeness, Traceability Ratio, Conflict Detection, Clock-Aware Escalation, Audit Reconstructability, State Correctness, and Evidence-Pack Generation. Their equations and zero-denominator handling are in `docs/metrics.md`.

The final evaluation uses four **controlled scenario replays over real-format artifacts**:

1. Silent Transitive / Ghost-Logger;
2. False Comfort;
3. Operational Outlier; and
4. Rapid Pivot.

They are not described as industrial case studies. Optional expert review is formative unless a suitable industrial evaluation is actually completed.

## 8. Baseline

The formal baseline is a conventional un-orchestrated PSIRT workflow in which an analyst separately checks SBOMs, advisories, VEX status, KEV, EPSS, reachability evidence, telemetry, asset criticality, mitigation records, and manually records decision rationale.

## 9. Non-claims

The artefact does not make legal decisions, submit regulatory reports, replace a PSIRT, provide industrial validation by itself, or completely resolve software-identity mismatch.


## 10. v0.2.1 implementation alignment

ADR-002 synchronizes the implementation with this semantic baseline before real-format ingestion:

- runtime vulnerable-function execution contributes to `A_t`, not automatically to `E_t`;
- active, traceable malicious-exploitation claims may set `E_t=1.0`;
- configured deadline posture is implemented independently of `recommended_state`;
- only explicit human events may set `authorized_state`;
- milestone completion or submission evidence is modeled separately from authorization;
- EvidencePack Schema v0.2 and the 34-field EC denominator remain unchanged; and
- the current YAML-driven Ghost-Logger scaffold remains temporary until the Stage 2 real-format vertical slice.
