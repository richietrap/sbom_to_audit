# Stage 6.4 performance and scale evaluation report

## Objective

Stage 6.4 characterizes the computational behaviour of the temporal evidence-orchestration prototype while preserving its accepted decision semantics. It answers a bounded engineering question: how does the implemented replay path behave as selected input and temporal dimensions increase in a controlled environment?

## Registered scale axes

The protocol varies one dimension at a time:

- `sbom_components`: 2 (the unscaled reference), 100, 1,000, 5,000, and 10,000 components;
- `telemetry_records`: 1, 10, 100, 500, and 1,000 records;
- `source_artifacts`: 15, 25, 50, 100, and 200 registered sources;
- `replay_events`: 5, 10, 25, 50, and 100 temporal events.

The unscaled Ghost-Logger case remains the semantic reference. Scale-only decoys must not alter the original five event decisions, final authorized state, final orchestration scores, or deadline outcomes.

## Measurement design

A fresh worker process is created for each workload. Three warm-up replays are excluded and ten replays are measured. The timed operation begins immediately before `replay_scenario` and ends immediately after it returns. This includes file validation, hashing and parsing, temporal replay, claim/conflict processing, scoring, deadline and authorization logic, and EvidencePack/audit assembly. Fixture generation, worker startup, and parent-result serialization are excluded.

Reported statistics include median and nearest-rank p95 wall time, median and p95 process CPU time, wall-time coefficient of variation, peak resident memory, input/output size, scale-unit throughput, and slowdown relative to the smallest registered value on the same axis.

## Interpretation

Observed timings are hardware- and runtime-specific. They must be accompanied by recorded environment metadata. The experiment has no latency acceptance threshold and cannot establish production capacity or an industrial service-level objective. A non-linear trend may reveal an implementation hotspot worthy of discussion, but it must not be generalized beyond the registered controlled workloads without additional evidence.

## Status

The Stage 6.4 repository outputs and paper assets are `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false`. They become eligible only through the later final evaluation-freeze process after exact-commit reproduction, independent result review, and completion or explicit disposition of the remaining evaluation dependencies.
