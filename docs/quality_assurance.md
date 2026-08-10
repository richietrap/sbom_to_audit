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

## Stage 6.1 baseline-evaluation safeguards

Stage 6.1 separates protocol construction from result execution. Protocol v0.2, the worksheet schema, scenario inputs, fairness mappings, and independent oracles are hashed before any final manual run. Neither evaluated workflow may define conflict truth, state expectations, or clock opportunities. Original analyst files are retained unchanged and normalized only into separately hashed evaluation views. The final Colab checkpoint must use an immutable commit or tag and rejects `main` and `master`.

The manual worksheet records confidence explicitly; missing confidence remains missing. Locked metrics remain unchanged, while common-field completeness, partial lineage, equivalent record-bundle generation, source accesses, and human Time to Decision are reported as supplemental controls. Automatic clock-safeguard ablation must not be described as proof that a human analyst would miss a deadline.


## Stage 6.1.1 execution-environment parity

A stage package must not be described as having passed static quality gates unless the exact
repository-declared development toolchain has been installed and executed in that packaging
environment. The expected installation is `python -m pip install -e ".[dev]"` inside an isolated
virtual environment. The release evidence must record Ruff, Mypy, Codespell, Yamllint, Hypothesis,
Python, and pytest versions together with the commands and outcomes.

Where an ephemeral assistant runtime cannot reach an approved package index, the local result must
fail closed as `TOOLCHAIN_NOT_PROVISIONED`; it must not be reported as a successful quality run.
GitHub Actions and the immutable Colab checkpoint remain authoritative independent environments,
but they do not retroactively justify an unexecuted local claim. Corrective releases increment the
stage patch suffix, such as Stage 6.1 to Stage 6.1.1.

### Reproducible quality-environment bootstrap

Stage 6.1.1 adds `scripts/bootstrap_quality_env.py` as the fail-closed provisioning entry
point. Running the script creates an isolated `.quality-venv`, installs the repository's
`.[dev]` extra, checks dependency integrity, and records the installed versions of Ruff,
Mypy, Codespell, Yamllint, and Hypothesis. A blocked package registry yields
`TOOLCHAIN_NOT_PROVISIONED`; it must never be reported as a passed static-quality gate.

## Stage 6.1.2 formatter-gate enforcement

Ruff lint and Ruff formatting are independent release gates. `ruff check .` verifies the configured lint rules, while `ruff format --check .` verifies canonical formatter output. A successful lint result does not satisfy the formatter gate. Packaging evidence must record both commands and outcomes separately, and either failure blocks release acceptance. Stage 6.1.2 records the formatter-only failure as BUG-018 and preserves all research semantics unchanged.

## Stage 6.1.3 final-edit formatter invalidation rule

Formatter evidence applies only to the exact repository tree on which it was generated. Any Python edit made after a successful formatter run, including a version-test or notebook-test edit, invalidates that evidence. The complete repository must therefore run `ruff check .` and `ruff format --check .` after all code, tests, notebooks, version markers, ADRs, changelog entries, and manifest updates are final. Packaging must occur only after those terminal gates pass. Checkpoint tests also assert the internal stage field so a copied notebook cannot retain a superseded checkpoint identity.

## Stage 6.1.4 YAML-quality and gate-parity rule

Syntactic YAML parsing is not equivalent to passing the repository's Yamllint contract. Sequence indentation, trailing whitespace, and end-of-file blank-line rules are release-blocking even when PyYAML loads the document successfully. Before packaging, the exact Yamllint scope from GitHub Actions must run against the final repository tree.

Where a pre-execution frozen YAML document requires formatting-only correction, the parsed object before and after the change must be identical, the evidence must be recorded, and the byte-level freeze must receive a new revision before any manual data are collected. Ruff lint, Ruff formatting, Mypy, Codespell, and Yamllint are reported as separate CI steps so no tool's result is hidden behind another command in a combined shell block.
## Stage 6.2 release discipline

For Stage 6.2, all implementation, tests, documentation, registry changes, and manifest updates must be complete before running mutating formatters. The final release sequence is: `ruff format .`, every non-mutating static gate, complete tests and coverage, Stage 6.1 freeze validation, Stage 6.2 validation, deterministic double-run comparison, repository validation, clean-tree confirmation, archive creation, and clean-extraction validation. Any edit after a successful gate invalidates that gate and restarts the sequence.

The Stage 6.2 notebook and release checker independently regenerate results and paper assets twice and compare their byte manifests. Candidate sensitivity counts are not promoted to paper evidence until exact-commit GitHub and Colab validation and the final evaluation freeze.

## Stage 6.3 mutation-quality gate

The Stage 6.3 release gate validates the mutation protocol and candidate hashes, compiles every registered mutant, runs deterministic mutation and asset generation twice, and rejects invalid, timed-out, missing, reordered, or source-drifted mutants. The accepted source tree is never mutated in place. Ruff formatting must run after the final source edit and before regenerating the Stage 6.3 result and asset manifests; every subsequent gate must then be rerun without further edits.

## Stage 6.4 performance-quality gate

Stage 6.4 separates deterministic correctness from non-deterministic timing. The release gate validates the registered scale protocol, a smoke benchmark in fresh worker processes, semantic decision equivalence, candidate-output hashes, environment metadata, paper-asset hashes, and the existing Stage 6.1–6.3 controls. It must not assert byte-identical latency or memory values across independent runs.

The local acceptance order remains strict: complete all source and documentation edits; apply Ruff lint fixes and Ruff formatting; run the full Stage 6.4 benchmark and regenerate its registered hashes/assets; then run only non-mutating quality, test, protocol, repository, release, and whitespace checks. Any source edit after the benchmark requires regeneration and a complete re-run.
