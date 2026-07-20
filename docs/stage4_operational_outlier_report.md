# Stage 4 Operational Outlier Pilot

## Objective

Test whether the frozen orchestration model distinguishes technical severity from operational impact, while preserving Stage 2 and Stage 3 behaviours and avoiding scenario-specific application code.

## Controlled pair

Operational Outlier and its counterfactual control use the same:

- CycloneDX component and dependency path;
- CVE and OSV alias bridge;
- NVD-shaped CVSS 3.1 score of 6.5 (`MEDIUM`);
- KEV membership and EPSS percentile;
- CSAF `under_investigation` status;
- byte-identical initial telemetry and later reachability artefacts;
- target deployment identity and timestamps;
- configured deadline profile; and
- mitigation status at the matched comparison event.

They differ in operational context:

| Scenario | Asset criticality | Deployment scope | I_t |
|---|---|---|---:|
| Operational Outlier | critical | widespread | 1.0 |
| Lower-impact control | medium | limited | 0.5 |

## Main trajectory

| Time | Evidence condition | Expected recommendation |
|---|---|---|
| T+2h | KEV-listed, medium CVSS, supplier under investigation, no confirmed reachability | Monitor |
| T+6h | Reachability confirmed in a critical, widespread water-control deployment | Report-Ready |
| T+12h | Human reporting authorization and early-warning completion | Report-Ready + authorized Report |
| T+72h | Verified mitigation and full-notification completion | Report-Ready + authorized Report |

## Counterfactual control

At T+6h the control has the same exploitation and applicability scores, the same non-asset source hashes, and the same deadline posture as the main scenario. Only the two frozen impact inputs differ: `asset_criticality` and `deployment_scope`. With `I_t=0.5`, the control remains `Monitor`. The comparison therefore exercises the configured impact threshold rather than a hidden difference in vulnerability intelligence, reachability, workflow timing, or deployment identity.

## Research interpretation

The pilot demonstrates controlled rule conformance: operational context can differentiate two otherwise matched cases, and CVSS is not used as a substitute for operational impact. It does not establish that the chosen thresholds are legally correct, empirically optimal, or generalisable to industrial PSIRT decisions.

## Preserved boundaries

- EvidencePack Schema remains v0.2.
- The 34 Evidence Completeness fields remain unchanged.
- Human authorization remains separate from recommendation.
- `under_investigation` remains an assessment status rather than a not-affected claim.
- Ghost-Logger conflict lifecycle and False Comfort scope reasoning remain regression-protected.
- Pilot outputs require GitHub and Colab checkpoint preservation before manuscript eligibility.
