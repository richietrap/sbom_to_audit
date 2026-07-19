# ADR-003: Quality Gates and Clean-Checkout Test Independence

- **Status:** Accepted
- **Approval date:** 2026-07-19
- **Software version:** 0.2.2
- **Schema version:** unchanged at 0.2

## Context

Stage 1.5 exposed two CI defects: invalid GitHub Action tags and tests that depended on
generated files excluded by `.gitignore`. Both passed in the development directory but
failed in a clean GitHub checkout. A multi-layer quality system is required before the
real-format ingestion work increases code and data complexity.

## Decision

1. Tests must create temporary outputs and must not depend on ignored generated files.
2. Ruff, Mypy, Codespell, Yamllint, actionlint, branch coverage, Hypothesis, Dependabot,
   repository validation, and deterministic replay are added as independent gates.
3. `scripts/validate_repository.py` is the authoritative structural validator.
4. `scripts/release_check.py` is the authoritative local pre-release command.
5. The initial branch-coverage ratchet is 70% and may only increase unless an ADR
   explicitly justifies a temporary reduction.
6. Missing real-format sources remain warnings until Stage 2; strict source validation
   becomes mandatory once the vertical slice is delivered.

## Consequences

- The EvidencePack schema, mandatory-field count, metrics, and state enumerations remain
  unchanged.
- CI becomes slower but materially more independent of the development environment.
- Immutable GitHub Action SHA pinning and mutation testing remain documented follow-ups.
