# ADR-008 — Uncertainty Resolution and Clock-Aware Escalation

**Status:** Accepted for Stage 5 pilot  
**Date:** 2026-07-20  
**Package:** v0.5.0  
**Schema impact:** None; EvidencePack Schema remains v0.2.

## Context

The frozen state rule requires a case to enter `Prepare` when uncertainty is high while exploitation evidence or operational impact meets its threshold. It also requires a case that remains in `Prepare` until the internal `tau_E=18h` safeguard to move to `Escalate`.

Earlier scenarios did not contain a replay opportunity for the Clock-Aware Escalation metric. Rapid Pivot therefore needs to exercise both the uncertainty mechanism and the elapsed-time safeguard without fabricating missingness, embedding a precomputed identity score, or conflating the internal safeguard with a statutory deadline.

## Decision

1. Rapid Pivot begins with:
   - a KEV-listed vulnerability;
   - high/broad operational context;
   - a unique name/version SBOM candidate whose PURL is absent;
   - no released EPSS, CSAF/VEX, telemetry, or identity-confirmation artefact.
2. Initial identity confidence is derived as `fuzzy_name_version=0.4`, not supplied as `gamma_id` by the scenario.
3. Missing evidence remains serialized as `None` in intermediate snapshots and contributes to the frozen `U_t` equation. The final EvidencePack remains schema-valid because all mandatory evidence is released before the final snapshot.
4. A later identity-resolution artefact confirms the component through its exact CPE and maps the canonical component PURL. The engine maps `exact_cpe_confirmed` to `gamma_id=0.7` after validating the selected BOM reference, target PURL, and CPE.
5. The primary replay delays the uncertainty-resolving evidence until T+20h. A T+18h event with prior state `Prepare` triggers `Escalate` under the internal safeguard.
6. The temporal control uses byte-identical sources, target, deadline profile, and event timestamps, but releases the same resolving evidence at T+12h. It reaches `Report-Ready` before T+18h and therefore does not trigger the safeguard.
7. State logs and audit events record `clock_safeguard_triggered` and the configured safeguard duration as sidecar/audit properties. No top-level schema field is added.

## Consequences

- The Clock-Aware Escalation metric is applicable for the primary replay and equals `1.0` under the controlled oracle.
- The control has no eligible Prepare-at-or-after-18h opportunity, so its CA value remains `null/not_applicable` rather than being treated as zero.
- The comparison demonstrates rule conformance and temporal selectivity, not legal deadline correctness, empirical optimality of 18 hours, or industrial effectiveness.
- The initial fuzzy identity and later CPE confirmation extend the identity path, but general identity resolution remains incomplete.
- Intermediate missing values are permitted inside replay calculation; final EvidencePack Schema v0.2 validation remains mandatory.
