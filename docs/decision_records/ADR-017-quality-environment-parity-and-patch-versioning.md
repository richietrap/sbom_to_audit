# ADR-017: Quality-Environment Parity and Corrective Stage Versioning

- **Status:** Accepted for Stage 6.1.1
- **Date:** 2026-07-29
- **Version:** 0.6.1.1

## Context

The Stage 6.1 package was assembled in an ephemeral execution environment where Ruff, Mypy,
Codespell, Yamllint, and Hypothesis were not installed. The package correctly declared those tools
in the `dev` extra and GitHub Actions installed them, but the local handoff described their absence
as a runtime limitation rather than provisioning the declared development environment. GitHub then
detected seven Ruff violations while all three regression-matrix jobs passed.

This exposed two governance defects: local quality success must not be claimed without executing the
same declared tools, and a post-stage corrective package must receive a distinct patch-stage and
package version rather than remaining an unnamed hotfix under the original version.

## Decision

1. The corrected checkpoint is **Stage 6.1.1**, package version **0.6.1.1**.
2. Stage 6.1 protocols, oracles, mappings, fixture values, freeze hashes, metrics, and research
   boundaries remain unchanged.
3. Packaging environments must create an isolated virtual environment and install `.[dev]` before
   static-quality and property-test claims are made.
4. Release evidence must record the installed versions and outcomes for Ruff, Ruff format, Mypy,
   Codespell, Yamllint, Hypothesis-backed pytest, coverage, repository validation, and deterministic
   checks.
5. If tool installation is blocked, the local gate is recorded as `TOOLCHAIN_NOT_PROVISIONED`; the
   package may only be called a pre-CI candidate until GitHub and immutable Colab checks pass.
6. Corrective stage releases use an added patch suffix and update package metadata, changelog,
   manifest, bug register, citation metadata, and version-consistency tests together.

## Consequences

- CI-detected formatting defects remain transparently recorded as BUG-017.
- No EvidencePack schema, 34-field EC denominator, metric equation, state trajectory, oracle, or
  manual-baseline protocol changes.
- Future handoffs fail closed when packaging-tool parity is absent.
- Stage 6.1.1 supersedes the unversioned Stage 6.1 quality hotfix, not the Stage 6.1 research design.

## Affected files

- `pyproject.toml`
- `src/sbom_to_audit/__init__.py`
- `CITATION.cff`
- `README.md`
- `CHANGELOG.md`
- `MANIFEST.md`
- `docs/bug_register.csv`
- `docs/quality_assurance.md`
- `docs/stage6_1_1_quality_correction_report.md`
- `tests/test_version_consistency.py`
- `scripts/bootstrap_quality_env.py`
- `tests/test_quality_bootstrap.py`

## Required verification

- package, module, citation, README, changelog, and manifest version markers agree;
- BUG-017 identifies v0.6.1.1;
- the Stage 6.1 freeze record verifies unchanged;
- regression, static-quality, property, coverage, repository, and deterministic gates pass in the
  fully provisioned GitHub and Colab environments.
