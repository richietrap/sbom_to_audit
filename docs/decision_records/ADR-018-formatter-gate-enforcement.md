# ADR-018: Formatter-Gate Enforcement Before Corrective Packaging

- **Status:** Accepted for Stage 6.1.2
- **Date:** 2026-07-29
- **Version:** 0.6.1.2

## Context

Stage 6.1.1 corrected seven Ruff lint findings, and `ruff check .` subsequently passed in GitHub Actions. The same quality job then failed at the distinct `ruff format --check .` command because 13 files did not match the repository-declared formatter output. The regression matrix continued to pass.

The defect did not affect the Stage 6.1 protocol, oracles, metrics, schemas, fixture values, or research outputs. It exposed a packaging-governance gap: lint conformance and formatter conformance are separate release gates, and passing one must not be used as evidence for the other.

## Decision

1. The corrected checkpoint is **Stage 6.1.2**, package version **0.6.1.2**.
2. Apply the exact formatter transformations reported by the authoritative GitHub `ruff format --check .` output to all 13 affected files.
3. Preserve Stage 6.1 and Stage 6.1.1 packages, notebooks, ADRs, and defect records as development history.
4. Packaging evidence must record separate outcomes for `ruff check .` and `ruff format --check .`.
5. A successful lint result cannot satisfy the formatter gate, and a formatter failure blocks release acceptance even when regression tests pass.
6. No Stage 6.1 protocol, oracle, mapping, worksheet, freeze target, locked metric, EvidencePack field, or research result is changed by this correction.

## Consequences

- BUG-018 records the formatter-only release defect.
- Stage 6.1.2 supersedes Stage 6.1.1 as the current pre-CI corrective candidate.
- The exact pushed commit must still pass GitHub Actions and the immutable Colab checkpoint before acceptance.
- Future corrective packages must execute both Ruff commands before packaging whenever the declared toolchain is available.

## Affected files

- 13 Python files identified by the GitHub formatter report
- `pyproject.toml`
- `src/sbom_to_audit/__init__.py`
- `CITATION.cff`
- `README.md`
- `CHANGELOG.md`
- `MANIFEST.md`
- `docs/bug_register.csv`
- `docs/quality_assurance.md`
- `docs/stage6_1_2_formatting_correction_report.md`
- `tests/test_version_consistency.py`
- `tests/test_stage6_1_notebook.py`
- `notebooks/stage6_1_2_colab_checkpoint.ipynb`

## Required verification

- `ruff check .` passes;
- `ruff format --check .` passes;
- Mypy, Codespell, Yamllint, Hypothesis-backed regression tests, coverage, repository validation, and freeze verification pass;
- package, module, citation, README, changelog, manifest, bug register, and notebook version markers agree; and
- the Stage 6.1 protocol freeze verifies unchanged.
