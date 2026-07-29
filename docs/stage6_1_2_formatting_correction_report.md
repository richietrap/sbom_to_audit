# Stage 6.1.2 Formatting Correction Report

## Status

`PRE_CI_FORMATTER_CORRECTIVE_CANDIDATE`

## Trigger

The Stage 6.1.1 GitHub quality workflow reported that `ruff check .` passed but `ruff format --check .` would reformat 13 files. Regression jobs for Python 3.10, 3.11, and 3.12 were not implicated.

## Correction

Stage 6.1.2 applies the exact formatter transformations shown by the GitHub report. Changes are limited to string-quote normalization, line wrapping, generator-expression layout, collection layout, and equivalent parenthesization. No executable semantics, experimental protocol, source data, oracle, metric, or generated research output is changed.

## Affected Python files

1. `scripts/build_stage6_1_paper_assets.py`
2. `scripts/export_stage6_1_baseline_packets.py`
3. `scripts/import_manual_baseline_results.py`
4. `scripts/run_stage6_1_comparison.py`
5. `scripts/validate_repository.py`
6. `scripts/validate_stage6_1_evaluation.py`
7. `src/sbom_to_audit/baseline/fairness_metrics.py`
8. `src/sbom_to_audit/baseline/manual_results.py`
9. `src/sbom_to_audit/baseline/worksheet_validation.py`
10. `tests/test_stage6_1_fairness_metrics.py`
11. `tests/test_stage6_1_manual_results.py`
12. `tests/test_stage6_1_oracles.py`
13. `tests/test_stage6_1_protocol.py`

## Governance

- Version: `0.6.1.2`
- Stage: `6.1.2`
- Defect: `BUG-018`
- Decision record: `ADR-018`
- EvidencePack schema: `0.2`, unchanged
- EC denominator: 34, unchanged
- Locked metrics: EC, TR, CD, CA, AR, SC, EPG, unchanged
- Stage 6.1 protocol and freeze hashes: unchanged

## Acceptance boundary

The correction remains a pre-CI candidate until the exact pushed commit passes the complete GitHub quality and regression workflows and is reproduced through the Stage 6.1.2 immutable-reference Colab checkpoint.
