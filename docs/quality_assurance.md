# Quality Assurance and Defect-Prevention Strategy

## Status

Stage 1.5.2 establishes independent quality gates before real-format ingestion begins.
These controls reduce, but do not eliminate, the possibility of defects. GitHub Actions
and the Colab checkpoints remain independent execution environments.

## Implemented safeguards

| Safeguard | Implementation | Gate |
|---|---|---|
| Formatting and common bug detection | Ruff lint and formatter | Pre-commit, quality CI, release check |
| Static type checking | Mypy with typed-stub dependencies | Pre-commit, quality CI, release check |
| Typographical checks | Codespell | Pre-commit, quality CI, release check |
| YAML validation | Yamllint and repository YAML parsing | Pre-commit, quality CI, release check |
| Workflow syntax validation | actionlint v1.7.12 | Quality CI |
| Dependency update monitoring | Dependabot for pip and GitHub Actions | Weekly pull requests |
| Manifest drift prevention | `validate_repository.py` and tests | Tests, pre-commit, CI, release check |
| Schema and metric lock checks | Repository validator and schema tests | Tests and CI |
| Scenario referential integrity | Duplicate and unknown-ID checks | Repository validator and tests |
| Self-contained tests | Tests generate their own temporary outputs | Regression CI |
| Deterministic replay | Two clean CLI runs compared byte-for-byte | Regression CI and release check |
| Branch coverage | Pytest-cov with a 70% initial ratchet | Quality CI and release check |
| Property-based testing | Hypothesis invariants | Regression suite |
| Known-defect tracking | `known_issues.md` and `bug_register.csv` | Governance review |
| Canonical release check | `scripts/release_check.py` | Before every tagged release |

## Fail-closed rules

The quality controls must reject malformed input, unsupported states, unknown source
references, duplicate identifiers, schema drift, merge markers, and release-blocking
placeholders. Missing Stage 2 source files are warnings until the real-format ingestion
milestone, after which `validate_repository.py --strict-sources` becomes mandatory.

## Coverage policy

The initial branch-coverage threshold is 70%. It is a ratchet, not a claim that 70% is
sufficient for production software. The threshold must not decrease without an ADR and
paper-impact assessment. Stage 2 must add parser and source-registry tests before new
modules are merged.

## Human review boundary

No automated check proves legal correctness, industrial fitness, or research validity.
Every stage still requires review of the ADR, changed-file inventory, test report,
coverage report, deterministic replay hashes, known limitations, and Colab checkpoint.
