# Stage 6 Matched Baseline Comparison Report

## Status

`PILOT_BASELINE_NOT_FROZEN / NOT_MANUSCRIPT_ELIGIBLE`

Stage 6 compares the artefact with a deterministic structured-but-unorchestrated PSIRT worksheet proxy across the four primary controlled scenario families and three matched controls.

## Comparison design

Both workflows receive identical committed source files at identical replay events. Source validation and format parsing are shared. The treatment is the orchestration layer: scoped claims, explicit confidence, numerical evidence variables, conflict lifecycle, clock safeguard, and EvidencePack construction.

The baseline remains capable of recording sources, tracking deadlines, preserving event logs, applying local evidence and operational context, and detecting direct contradictions. It is therefore not an empty or deliberately incompetent baseline.

## Pilot results across the four primary families

| Metric | Artefact mean | Baseline mean | Difference |
|---|---:|---:|---:|
| EC | 1.000000 | 0.764706 | 0.235294 |
| TR | 1.000000 | 0.000000 | 1.000000 |
| CD | 1.000000 | 1.000000 | 0.000000 |
| CA | 1.000000 | 0.000000 | 1.000000 |
| AR | 1.000000 | 1.000000 | 0.000000 |
| SC | 1.000000 | 0.708333 | 0.291667 |
| EPG | 1.000000 | 0.000000 | 1.000000 |

`CD` and `CA` use only primary scenarios with an applicable denominator. The strict baseline `TR=0` occurs because the worksheet preserves four of five lineage elements but does not assign standardized claim confidence; its partial lineage ratio is reported separately rather than hidden.

## Mechanism-level divergences

Five event decisions differ:

- False Comfort: the baseline applies a supplier `known_not_affected` status without adjudicating the declared product-variant scope, then treats later local reachability as a direct conflict. The artefact records a scope mismatch and reaches `Report-Ready` without a false conflict.
- Rapid Pivot at T+18h: the baseline remains `Prepare`; the artefact invokes the frozen internal clock safeguard and reaches `Escalate`.

The baseline correctly matches Ghost-Logger, Operational Outlier, and all three matched controls. This prevents the comparison from being interpreted as a universal baseline failure.

## Conflict quality

Both workflows detect the one seeded Ghost-Logger conflict, so conflict recall is equal. Across the full controlled suite:

- artefact conflict precision: `1.0`;
- baseline conflict precision: `0.5`.

The baseline's additional episode is a scope-blind False Comfort false positive.

## Review-operation proxy

The comparison records 86 unique source ingestions for the artefact and 273 accumulated source appearances across repeated baseline worksheet reviews. This is a process-operation proxy only. It is not analyst time, cognitive effort, or a productivity measurement.

## Interpretation

Stage 6 supplies the first controlled answer to RQ5: within the frozen scenario suite, the orchestration layer improves completeness, strict claim-level traceability, clock-aware escalation, state-oracle agreement, conflict precision, and EvidencePack generation. It does not improve the minimal event-field audit-reconstructability metric or seeded-conflict recall, where the workflows tie.

The result remains a controlled computational comparison. Practitioner evaluation, robustness testing, mutation testing, and stable-environment performance testing remain necessary before final conclusions.
