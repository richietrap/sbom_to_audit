# ADR-007: Operational Impact and Technical-Severity Context

- **Status:** Accepted
- **Date:** 2026-07-20
- **Software version:** 0.4.0
- **EvidencePack schema:** 0.2 (unchanged)

## Context

The Operational Outlier scenario tests whether the orchestration model treats operational impact as an independent decision input rather than using technical severity as a proxy for organisational consequence. Stage 3 did not preserve a normalized CVSS context because its scenarios did not require a matched technical-severity comparison.

A second semantic issue was identified while designing the scenario: CSAF `under_investigation` is an assessment state, not a negative affectedness conclusion. Converting it into `product_affectedness=false` would fabricate supplier assurance and could suppress a legitimate case.

## Decision

1. Add an offline NVD API 2.0 snapshot parser that extracts the target CVE's primary CVSS metric, base score, base severity, and vector.
2. Store CVSS values as contextual fields in `vulnerability_intelligence` and as traceable claims. They do not directly change the frozen `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, or `C_t` equations.
3. Treat CSAF affected and not-affected statuses as affectedness claims. Treat `under_investigation` as `supplier_assessment_status=under_investigation`, not as `product_affectedness=false`.
4. Pair Operational Outlier with a counterfactual control that reuses the exact same non-asset source files, target-deployment identity, timestamps, and deadline profile while changing only `asset_criticality` and `deployment_scope`.
5. Continue to derive `I_t` solely from the frozen asset-criticality and deployment-scope mapping.

## Consequences

- A CVSS 6.5 MEDIUM vulnerability can remain non-extreme in technical-severity context while high operational impact contributes `I_t=1.0`.
- With matched `E_t=0.85` and `A_t=1.0`, the main scenario reaches `Report-Ready`, while the lower-impact control remains `Monitor` with `I_t=0.5`.
- CVSS is preserved for interpretation and paired comparison but is not silently inserted into the state-transition rule.
- Supplier investigation status cannot generate a false not-affected claim.

## Limitations

The NVD input is a controlled NVD-shaped snapshot, not a live NVD record. CVSS is a technical-severity context, not an operational-impact measure or legal reportability rule. The paired control isolates the configured impact mechanism within a fictional scenario and does not establish external decision accuracy.
