# ADR-014: Use Workflow-Independent Event-Level Evaluation Oracles

- **Status:** Accepted for Stage 6.1 implementation
- **Date:** 2026-07-24
- **Version:** 0.6.1

## Context

The Stage 6 pilot calculated conflict precision using the number of conflict episodes detected
by the baseline in Ghost-Logger as the count of true conflicts. That allowed one evaluated
workflow to participate in defining ground truth and compared counts rather than exact events.
A workflow could therefore receive perfect precision after detecting the wrong event, provided
the total count matched.

## Decision

Create and freeze three exhaustive event-level oracles before final execution:

- `state_oracle_v0.1.yaml`;
- `conflict_oracle_v0.1.yaml`;
- `clock_opportunity_oracle_v0.1.yaml`.

Conflict precision and recall compare exact `(scenario_id, event_id)` detections against the
conflict oracle. The oracles are derived from the controlled scenario design, not from either
workflow output. The event universes must match. Changes after execution require a new
oracle version, ADR, protocol freeze, and complete rerun.

## Consequences

Ground truth is independent of the compared systems. False Comfort's scope-mismatched
supplier assurance is explicitly a negative conflict case, while Ghost-Logger's T+10 event is
the single seeded true conflict. State correctness remains controlled rule conformance rather
than external legal accuracy.
