# Stage 6.1.3 Formatter and Checkpoint-Metadata Correction Report

## Status

`PRE_CI_FINAL_FORMATTER_CORRECTIVE_CANDIDATE`

## Trigger

GitHub Actions reported that `ruff check .` passed but `ruff format --check .` would reformat `tests/test_stage6_1_notebook.py`. The required transformation was limited to top-level definition spacing and the trailing blank line.

A separate review found that the Stage 6.1.2 checkpoint report contained `stage: 6.1.1`.

## Corrections

- Applied the exact remaining Ruff formatter change.
- Corrected the Stage 6.1.2 checkpoint report metadata in the current repository.
- Added a Stage 6.1.3 immutable-reference checkpoint notebook.
- Added explicit stage-field regression assertions.
- Incremented the package and checkpoint to 0.6.1.3 / Stage 6.1.3.
- Added ADR-019, BUG-019, and BUG-020.

## Research boundary

No baseline protocol, evaluation oracle, fairness mapping, worksheet field, scenario event, state expectation, conflict label, clock opportunity, EvidencePack field, metric definition, or candidate result changed.

## Acceptance boundary

Stage 6.1.3 remains a pre-CI candidate until all GitHub quality and regression jobs pass and the exact commit is reproduced through the Stage 6.1.3 Colab checkpoint.
