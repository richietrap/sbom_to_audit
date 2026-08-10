# ADR-024 — Stage 6.4 performance and scale evaluation

## Status

Accepted for the Stage 6.4 evaluation candidate. The resulting measurements remain `CANDIDATE_NOT_FROZEN`.

## Decision

Stage 6.4 measures the accepted orchestration path using four one-factor-at-a-time scale axes: CycloneDX component count, runtime-telemetry record count, registered source-artifact count, and replay-event count. The reference case is Ghost-Logger. Synthetic decoys and post-satisfaction no-op temporal events may enlarge the workload only when the original decision semantics remain unchanged.

Each workload executes in a fresh Python process. Fixture generation and interpreter/process startup are excluded from the timed operation. Warm-up replays are excluded from statistics. The measured operation is `replay_scenario`, including source validation, hashing and parsing, claim generation, temporal replay, conflict and score evaluation, authorization and deadline evaluation, and EvidencePack/audit-ledger assembly.

The registered full profile uses three warm-up runs and ten measured runs per workload. Median wall time is the primary latency statistic and nearest-rank p95 wall time is the tail statistic. CPU time, peak resident memory, input/output bytes, relative slowdown, and scale-unit throughput are supporting measurements.

## Timing non-determinism boundary

Performance observations are inherently environment-specific and are not expected to be byte-identical across independent runs. Release validation therefore requires deterministic workload definitions and semantic decision fingerprints, valid measurement structure, and exact observed-output hashes for the committed candidate. It does not require equal latency values across machines or repeated executions.

No performance threshold, service-level objective, production-capacity claim, or industrial throughput target is introduced. Results from non-equivalent hardware environments must not be pooled.

## Research boundary

The scale fixtures are controlled synthetic extensions of a fictional scenario. They are not industrial traces, production load tests, legal validation, or evidence that the prototype is suitable for a particular deployment size. Final manuscript use requires exact-commit reproduction, independent result audit, and the final evaluation freeze.
