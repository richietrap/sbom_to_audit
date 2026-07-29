# Stage 6.1 Manual-Assisted PSIRT Baseline Analyst Brief

## Objective

Review the same evidence releases supplied to the orchestration artefact and record a PSIRT
posture using ordinary inspection tools. The experiment evaluates evidence organization and
orchestration, not raw JSON-reading endurance.

## Procedure

- Process scenarios in the assigned order.
- Open only the event packet released for the current event.
- Record source accesses, observations, decision rationale, confidence, timing, conflicts,
  authorization, and clock concerns before moving to the next event.
- Do not inspect expected states, generated claims, conflict reports, or artefact outputs.
- Do not use custom scripts that normalize, join, score, or adjudicate the evidence.
- Do not revise an earlier decision after seeing a later release; add a new event decision.

The allowed and prohibited tools are defined in `allowed_tools.yaml`.
