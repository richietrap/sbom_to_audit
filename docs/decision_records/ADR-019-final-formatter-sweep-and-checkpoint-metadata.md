# ADR-019: Final Formatter Sweep and Checkpoint Metadata Coherence

- **Status:** Accepted for Stage 6.1.3
- **Date:** 2026-07-29
- **Version:** 0.6.1.3

## Context

Stage 6.1.2 applied every formatter transformation reported by the preceding GitHub quality run. During the same corrective packaging cycle, the Stage 6.1 notebook test was then extended with a new Stage 6.1.2 assertion. That final edit occurred after the formatter-equivalence work and was not subjected to a fresh complete-repository formatter pass. GitHub therefore reported one remaining unformatted test file.

Review also identified that the Stage 6.1.2 checkpoint report retained `stage: 6.1.1` from the copied Stage 6.1.1 notebook, even though its package version and checkpoint identifier were Stage 6.1.2.

Neither defect changes the Stage 6.1 experimental protocol, oracles, mappings, worksheet, metrics, schemas, fixture values, or candidate results. The first is a release-process defect and the second is checkpoint metadata drift.

## Decision

1. Release the correction as **Stage 6.1.3**, package version **0.6.1.3**.
2. Apply the exact Ruff formatter output to the remaining notebook test.
3. Correct the Stage 6.1.2 checkpoint report metadata in the current repository while retaining the previously distributed Stage 6.1.2 archive as immutable development history.
4. Add a Stage 6.1.3 checkpoint notebook whose checkpoint ID, stage field, package version, paths, and immutable-reference sentinel agree.
5. Extend regression tests to assert checkpoint stage metadata, not only package version and mutable-reference rejection.
6. Run `ruff check .` and `ruff format --check .` only after every release-metadata, notebook, test, manifest, ADR, and changelog edit is complete. Any subsequent Python edit invalidates the formatter evidence and requires the formatter gates to be rerun.
7. Preserve the Stage 6.1 protocol freeze and all research semantics unchanged.

## Consequences

- BUG-019 records the final formatter regression.
- BUG-020 records the Stage 6.1.2 checkpoint metadata drift.
- Stage 6.1.3 supersedes Stage 6.1.2 as the current pre-CI corrective candidate.
- A successful GitHub Actions run and immutable Colab reproduction remain mandatory before acceptance.

## Affected files

- `tests/test_stage6_1_notebook.py`
- `notebooks/stage6_1_2_colab_checkpoint.ipynb`
- `notebooks/stage6_1_3_colab_checkpoint.ipynb`
- release-version markers
- `CHANGELOG.md`
- `MANIFEST.md`
- `docs/bug_register.csv`
- `docs/quality_assurance.md`
- `docs/stage6_1_3_formatter_and_metadata_correction_report.md`
- `tests/test_version_consistency.py`

## Required verification

- Ruff lint and formatter gates pass on the complete final repository;
- Mypy, Codespell, Yamllint, Hypothesis-backed tests, branch coverage, repository validation, and freeze verification pass;
- Stage 6.1.2 and Stage 6.1.3 notebook metadata assertions pass;
- version markers agree at 0.6.1.3; and
- the Stage 6.1 protocol freeze verifies byte-for-byte unchanged.
