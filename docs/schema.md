# EvidencePack Schema v0.2

The canonical machine-readable schema is `schemas/evidencepack_v0.2.schema.json`. This document explains the locked structure and the Evidence Completeness denominator.

## Top-level structure

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
| `source_artifacts` | Normalized artifact inventory with hashes and timestamps. |
| `audit_log` | Ordered reconstruction events. |

## Mandatory fields for Evidence Completeness

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

## Claim traceability contract

A claim is traceable only when all of these fields are populated:

- `source_artifact_id`;
- `source_uri`;
- `source_hash`;
- `timestamp`; and
- `confidence`.

Claims also carry `claim_id`, `proposition`, and `value` so the conflict detector can compare active assertions.

## Allowed states

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

The prototype never automatically sets `authorized_state`.
