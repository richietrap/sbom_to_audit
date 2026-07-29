# ADR-016: Manual Baseline Execution, Blinding, and Original-Record Preservation

- **Status:** Accepted for Stage 6.1 implementation
- **Date:** 2026-07-24
- **Version:** 0.6.1

## Context

A fair baseline must isolate orchestration rather than parser skill or deliberate tool
deprivation. It must also prevent the analyst from adjusting decisions to match automated
outputs. The project owner has previously seen Stage 6 automated results, so any
researcher-executed baseline by the same person cannot be described as fully blinded.

## Decision

1. Permit ordinary inspection tools declared in `allowed_tools.yaml`.
2. Prohibit the prototype, generated claims, conflict reports, expected labels, custom
   orchestration scripts, and integrated platforms implementing the intervention.
3. Release evidence event by event through blinded packets that contain no expected outcome.
4. Require source-access, observation, decision, conflict, confidence, and timing records.
5. Preserve and hash every original completed file before normalization.
6. Record prior exposure to automated outputs in `declaration.yaml`.
7. Classify an exposed run as `NON_BLINDED_RESEARCHER_EXECUTED`; do not discard or hide it.
8. Prefer an analyst who has not seen automated outputs for the final comparison where
   practicable.

## Consequences

The baseline is operationally fairer and auditable. Researcher execution remains useful but is
not independent practitioner validation. Original records cannot be silently corrected; any
amendment requires a separately logged correction with actor, timestamp, reason, and impact.
