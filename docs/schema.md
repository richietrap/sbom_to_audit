# EvidencePack Schema v0.2

**Semantic clarification:** v0.2.1  
**Canonical schema:** `schemas/evidencepack_v0.2.schema.json`

This document explains the locked structure, Evidence Completeness denominator, traceability contract, and schema-compatible v0.2.1 audit-event extensions.

## 1. Top-level structure

| Block | Purpose |
|---|---|
| `schema_version` | Frozen schema identifier, exactly `0.2`. |
| `case_metadata` | Case identifier, deterministic generation time, clock start, and `delta_t_hours`. |
| `product_context` | Product, version, PURL, and source SBOM reference. |
| `identity_resolution` | Primary identifier, matching method, and `gamma_id`. |
| `vulnerability_intelligence` | CVE, KEV status, and EPSS percentile. |
| `supplier_assertions` | CSAF/VEX status and source reference. |
| `local_evidence` | Execution, reachability, and telemetry references. |
| `asset_context` | Criticality and deployment scope. |
| `mitigation_context` | Current mitigation status. |
| `orchestration_metrics` | `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, and `C_t`. |
| `decision_state` | Recommendation, human-authorization boundary, rationale, and `authorized_state`. |
| `claims` | Atomic, source-linked assertions used for traceability and conflict detection. |
| `source_artifacts` | Normalized artefact inventory with hashes and timestamps. |
| `audit_log` | Ordered reconstruction events, including v0.2.1 deadline and human-action events. |

The presence of `M_t` in `orchestration_metrics` is preserved. Under semantic version v0.2.1 it is payload and audit context rather than an input to the evidential recommendation function `R_t`.

## 2. Mandatory fields for Evidence Completeness

EvidencePack v0.2 has exactly 34 mandatory fields for the `EC` denominator.

| ID | Field path |
|---|---|
| F01 | `case_metadata.case_id` |
| F02 | `case_metadata.generated_at` |
| F03 | `case_metadata.clock_start_time` |
| F04 | `case_metadata.delta_t_hours` |
| F05 | `product_context.product_id` |
| F06 | `product_context.product_version` |
| F07 | `product_context.purl` |
| F08 | `product_context.sbom_reference` |
| F09 | `identity_resolution.primary_identifier` |
| F10 | `identity_resolution.matching_method` |
| F11 | `identity_resolution.gamma_id` |
| F12 | `vulnerability_intelligence.cve_id` |
| F13 | `vulnerability_intelligence.cisa_kev_status` |
| F14 | `vulnerability_intelligence.epss_percentile` |
| F15 | `supplier_assertions.csaf_vex_status` |
| F16 | `supplier_assertions.csaf_reference` |
| F17 | `local_evidence.execution_observed` |
| F18 | `local_evidence.reachability_confirmed` |
| F19 | `local_evidence.telemetry_reference` |
| F20 | `asset_context.asset_criticality` |
| F21 | `asset_context.deployment_scope` |
| F22 | `mitigation_context.mitigation_status` |
| F23 | `orchestration_metrics.E_t` |
| F24 | `orchestration_metrics.A_t` |
| F25 | `orchestration_metrics.I_t` |
| F26 | `orchestration_metrics.M_t` |
| F27 | `orchestration_metrics.U_t` |
| F28 | `orchestration_metrics.C_t` |
| F29 | `decision_state.recommended_state` |
| F30 | `decision_state.human_authorization_required` |
| F31 | `decision_state.rationale` |
| F32 | `claims[]` |
| F33 | `source_artifacts[]` |
| F34 | `audit_log[]` |

Population rules:

- a missing key is unpopulated;
- `null` is unpopulated;
- an empty string is unpopulated;
- an empty array is unpopulated;
- numeric zero is populated; and
- Boolean `false` is populated.

`decision_state.authorized_state` is structurally required and must be one of `Report`, `Document No-Report`, or `null`. It is not a thirty-fifth EC field.

## 3. Claim traceability contract

A claim is traceable only when all of these fields are populated:

- `source_artifact_id`;
- `source_uri`;
- `source_hash`;
- `timestamp`; and
- `confidence`.

Claims also carry `claim_id`, `proposition`, and `value`. The planned scoped claim model additionally records product, component, vulnerability, deployment, and temporal scope without changing the v0.2 top-level schema.

## 4. Allowed states

`recommended_state`:

- `Monitor`
- `Prepare`
- `Escalate`
- `Report-Ready`
- `Report`
- `Document No-Report`

`authorized_state`:

- `Report`
- `Document No-Report`
- `null`

The automatic evidential recommendation function does not originate `Report`. The schema retains it for compatibility with human-authorized or historical records.

## 5. Audit-log base contract

Every `audit_log[]` entry must contain:

- `event_id`;
- `timestamp`;
- `actor`;
- `action`;
- `input_references`; and
- `output_state`.

The JSON Schema permits additional properties. Semantic version v0.2.1 uses those additional properties to record deadline status, authorization, and milestone satisfaction without adding a new top-level block.

### 5.1 Deadline-status event

A schema-compatible deadline event is:

```json
{
  "event_id": "evt-deadline-0004",
  "timestamp": "2026-07-13T14:38:00Z",
  "actor": "deadline_engine",
  "action": "deadline_status_changed",
  "input_references": [
    "clock-start-event",
    "deadline-profile-cra-active-exploitation"
  ],
  "output_state": "Report-Ready",
  "milestone_id": "early_warning",
  "previous_status": "Due Soon",
  "new_status": "Breach Imminent",
  "delta_t_hours": 22,
  "clock_basis": "internal_awareness_proxy"
}
```

`output_state` remains the evidential recommendation at that event. `new_status` is the separate configured deadline posture.

### 5.2 Human-authorization event

```json
{
  "event_id": "evt-auth-0005",
  "timestamp": "2026-07-13T15:00:00Z",
  "actor": "psirt_legal_reviewer",
  "action": "authorized_state_recorded",
  "input_references": ["evidence-pack-version-4"],
  "output_state": "Report-Ready",
  "authorized_state": "Report",
  "rationale_reference": "decision-record-0005"
}
```

This event records human intent or authorization. It does not prove that a submission was completed.

### 5.3 Milestone-satisfaction event

```json
{
  "event_id": "evt-submit-0006",
  "timestamp": "2026-07-13T15:12:00Z",
  "actor": "submission_recorder",
  "action": "milestone_satisfied",
  "input_references": ["submission-receipt-0006"],
  "output_state": "Report-Ready",
  "milestone_id": "early_warning",
  "new_status": "Satisfied",
  "satisfaction_evidence_id": "submission-receipt-0006",
  "satisfied_at": "2026-07-13T15:12:00Z",
  "timeliness": "on_time"
}
```

A valid completion or submission record, not authorization alone, changes the relevant deadline milestone to `Satisfied`.

## 6. Deadline data placement

EvidencePack v0.2 does not add a required `deadline_context` block.

- current and historical deadline changes are represented in `audit_log[]`;
- scenario and benchmark sidecars may contain a convenience summary of `D_t`;
- Execution Latency remains in metrics or benchmark sidecars;
- a required top-level deadline block would require EvidencePack v0.3.

## 7. Schema-version rule

- documentation or semantic clarification without a structural schema change: v0.2.1;
- adding, removing, renaming, or changing the type of a required field or top-level block: v0.3.
