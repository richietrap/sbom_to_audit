# Quality Assurance and Defect-Prevention Strategy

## Status

Stage 2.0.1 retains the independent quality gates established before real-format
ingestion and adds cross-output semantic invariants. These controls reduce, but do not
eliminate, the possibility of defects. GitHub Actions and Colab remain independent
execution environments, not independent semantic oracles.

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
| Cross-output semantic consistency | `C_t` must equal the presence of active conflict-history records | Pipeline, CLI, and integration tests |
| Explicit lifecycle closure | An active conflict may not disappear without a registered resolution artefact | Pipeline fail-closed invariant and regression test |
| Known-defect tracking | `known_issues.md` and `bug_register.csv` | Governance review |
| Canonical release check | `scripts/release_check.py` | Before every tagged release |

## Fail-closed rules

The quality controls must reject malformed input, unsupported states, unknown source
references, duplicate identifiers, schema drift, merge markers, and release-blocking
placeholders. Missing Stage 2 source files are warnings until the real-format ingestion
milestone, after which `validate_repository.py --strict-sources` becomes mandatory.

Conflict history is also fail closed. A final `C_t=false` result cannot coexist with an
`active` retained conflict, and a previously active conflict cannot disappear merely
because the current-state calculation no longer sees it. The replay requires an explicit,
registered resolution artefact and emits a separate resolution audit event.

## Safeguard limitation exposed by BUG-004

The Stage 2.0 conflict-lifecycle defect passed CI and Colab because both environments
executed the same incomplete assertions. Schema validation established structural
validity, deterministic replay established repeatability, and the state oracle established
the correct recommendation. None of those checks compared the final state variable with
the retained sidecar status. Independent execution therefore reproduced the same semantic
error consistently.

For every new sidecar or paper-facing output, development must now identify and test:

1. the authoritative source of truth;
2. cross-output invariants;
3. lifecycle transitions, not only final values; and
4. conditions that must fail closed rather than being silently normalized.

## Coverage policy

The initial branch-coverage threshold is 70%. It is a ratchet, not a claim that 70% is
sufficient for production software. The threshold must not decrease without an ADR and
paper-impact assessment. Stage 2 must add parser and source-registry tests before new
modules are merged.

## Human review boundary

No automated check proves legal correctness, industrial fitness, or research validity.
Every stage still requires review of the ADR, changed-file inventory, test report,
coverage report, deterministic replay hashes, known limitations, and Colab checkpoint.

## Stage 5 temporal-control safeguards

Rapid Pivot adds paired-control assertions requiring the primary and control manifests to have identical source catalogs, targets, deadline profiles, and event timestamps. Tests verify that only the release event for the uncertainty-resolving artefacts differs. The release gate also checks that the main replay has exactly one eligible clock-safeguard opportunity and trigger, while the control has none. This prevents deadline-profile drift, hidden source changes, or a conflict event from being misreported as clock-aware escalation.
