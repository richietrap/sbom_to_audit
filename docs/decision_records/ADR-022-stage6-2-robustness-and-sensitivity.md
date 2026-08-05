# ADR-022: Stage 6.2 robustness and sensitivity evaluation

- **Status:** Accepted for implementation; results remain candidate until external gates and final freeze
- **Date:** 2026-08-03
- **Decision owners:** Project author and artefact implementation workflow
- **Related:** ADR-013 through ADR-021; Stage 6.1 pre-execution freeze 002

## Context

The pre-established evaluation sequence places robustness and sensitivity testing after the matched baseline package. The blinded human execution is deferred, but the Stage 6.1.5 protocol, packets, worksheet, oracles, and reproducibility checkpoint remain frozen. The next technical objective is therefore to test whether the accepted prototype changes its outputs deterministically and explainably when evidence, identity, scope, timing, thresholds, or input validity changes.

The reviewers asked for stronger operational detail, explicit variable calculation, clearer handling of incomplete or conflicting evidence, and more substantial validation. Robustness testing addresses those concerns without representing controlled perturbations as industrial observations.

## Decision

Stage 6.2 will provide a registered, deterministic evaluation harness with four complementary layers:

1. **Threshold sensitivity:** replay all seven controlled scenarios at baseline thresholds and offsets of -0.10, -0.05, +0.05, and +0.10.
2. **Clock sensitivity:** replay Rapid Pivot and its matched control at internal safeguards of 14, 16, 18, 20, and 22 hours.
3. **Single-factor perturbations:** vary identity confidence, KEV status, EPSS percentile, VEX state, execution, reachability, criticality, deployment scope, mitigation, conflict, malicious-exploitation observation, and telemetry-reference missingness one factor at a time.
4. **Negative integrity cases:** prove fail-closed handling for missing or malformed inputs, duplicate artefacts, path traversal, invalid chronology, future-dated releases, and unsupported values.

The evaluation must produce machine-readable CSV and JSON outputs, an output manifest, a scenario-stability summary, and data-generated candidate paper assets. The Stage 6.2 Colab checkpoint must reproduce the results and assets twice from an exact detached commit and compare every byte.

## Locked boundaries

Stage 6.2 does not change:

- EvidencePack Schema v0.2;
- the 34-field EC denominator;
- EC, TR, CD, CA, AR, SC, or EPG definitions;
- accepted scenario evidence or expected-state oracles;
- Stage 6.1 protocol, mappings, workbook, or pre-execution freeze;
- the human-authorization boundary;
- the baseline value `tau_E = 18h` used by the accepted artefact.

Alternative thresholds and clock values exist only inside the evaluation harness. They are prototype sensitivity parameters, not legal or empirical recommendations.

## Research and reporting boundaries

- Controlled perturbations are not real organisational incidents.
- State changes demonstrate model sensitivity, not legal correctness.
- Stable outcomes demonstrate consistency within the registered scenario space, not industrial generalisability.
- Candidate results remain `manuscript_eligible: false` until GitHub, exact-commit Colab reproduction, independent review, and the final evaluation freeze.
- The deferred blinded manual baseline remains required before final RQ5 comparative claims are frozen.

## Consequences

Positive consequences include explicit boundary testing, a reproducible transition matrix, negative security evidence, and paper-ready data products with provenance. Costs include a larger evaluation surface and the need to distinguish carefully between model behaviour, implementation correctness, and external validity.
