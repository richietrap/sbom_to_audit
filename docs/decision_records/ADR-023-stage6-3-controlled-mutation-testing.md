# ADR-023: Controlled mutation testing for decision-safety logic

- **Status:** Accepted for Stage 6.3 candidate implementation
- **Date:** 2026-08-05
- **Decision owner:** Artefact implementation workstream

## Context

The repository already contains unit, property, scenario, negative-case, deterministic-replay,
and clean-room checks. Passing tests alone, however, does not show whether those checks would
fail when plausible faults are introduced into the temporal state machine, conflict handling,
authorisation boundary, traceability controls, identity uncertainty, evidence semantics, or
metric calculations.

Stage 6.3 therefore evaluates the sensitivity of the verification suite to a bounded,
pre-registered set of first-order source mutations. It follows the accepted Stage 6.2
checkpoint at commit `36cb40fed9be39a19da25df70bb524c2cc05e316` and preserves that
checkpoint's Colab evidence hash.

## Decision

Register exact-text mutants in `evaluation/stage6_3_mutation_protocol_v0.1.yaml`. Apply one
mutant at a time only within a disposable repository copy. Compile the mutated target and run
its declared test nodes under a fixed timeout.

Two transparent phases are recorded:

1. the baseline phase uses only tests that existed before Stage 6.3; and
2. the strengthened phase adds a named safety test only where a baseline survivor exposed a
   specific verification gap.

Outcomes are `KILLED`, `SURVIVED`, `INVALID`, or `TIMEOUT`. Mutation score excludes invalid
and timed-out mutants and is interpreted by family, not as a universal quality threshold.
Equivalent mutants are not inferred automatically.

The accepted production source is never mutated in place. Candidate mutation outputs and
paper assets remain `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false` until exact-commit
GitHub and Colab reproduction and the later evaluation freeze.

## Consequences

- Surviving baseline mutants remain visible rather than being silently removed.
- Added safety tests are explicitly attributable to the survivor that motivated them.
- Exact-text mutations fail closed after source refactoring instead of silently targeting a
  different expression.
- A high bounded mutation score cannot be represented as proof of legal correctness,
  production security, exhaustive fault coverage, or absence of defects.
- The Stage 6.1 blinded manual baseline remains deferred and unchanged.
