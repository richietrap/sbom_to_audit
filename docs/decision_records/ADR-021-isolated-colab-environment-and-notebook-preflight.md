# ADR-021: Isolated Colab environment and notebook-wide preflight

- **Status:** Accepted
- **Date:** 2026-07-30
- **Decision owners:** Artefact implementation and evaluation workflow
- **Supersedes:** The Stage 6.1 through Stage 6.1.4 checkpoint environment pattern only
- **Preserves:** ADR-012 through ADR-020, EvidencePack Schema v0.2, all locked metrics, and the Stage 6.1 protocol freeze

## Context

The Stage 6.1.4 Colab checkpoint installed the project and its development dependencies into the
Colab kernel environment and then ran `pip check` against that shared environment. Google Colab
contains many unrelated preinstalled packages. A conflict among those packages can therefore
cause `pip check` to fail even when the repository's own dependency set is internally consistent.
The same notebook subsequently invoked project scripts through the global `python` command,
which meant the checkpoint did not reproduce the isolated-environment pattern already used by
earlier Stage 2 through Stage 6 notebooks.

The failure was detected before a Stage 6.1 checkpoint evidence bundle or manual-baseline result
was accepted. It did not change protocol content, oracle values, metrics, scenarios, or research
outputs, but it exposed a notebook-release assurance gap.

## Decision

Stage 6.1.5 adopts the following checkpoint contract:

1. The checkpoint accepts only an exact 40-character Git commit SHA.
2. The repository is checked out in detached-HEAD mode and the resolved commit must equal the
   requested SHA.
3. A dedicated virtual environment is created under `/content`; no project dependency is
   installed into the Colab kernel environment.
4. Package installation, `pip check`, compilation, quality tools, tests, validation scripts,
   deterministic replays, packet export, and optional manual-result processing all use the
   isolated interpreter explicitly.
5. The canonical `scripts/release_check.py` report is the primary repository-wide gate; the
   notebook verifies that every required check is present and successful.
6. Online historical EPSS verification and verified replay eligibility remain fail-closed by
   default.
7. Exported baseline packets are independently checked for safe paths, unique event identities,
   registry-to-manifest hashes, copied-artifact hashes, manifest identity, and recursive exclusion
   of oracle or automated-result keys.
8. Manual-result ZIP extraction rejects absolute, backslash, traversal, non-canonical, duplicate-normalized, and file-parent-collision paths as well as encryption, corruption, symbolic links, special files, and oversized archives; validated regular files are written exclusively in bounded chunks rather than through bulk extraction.
9. Every external command writes a complete log for each attempt, and the final checkpoint bundle contains logs,
   release reports, frozen controls, packet outputs, checksums, and optional manual-result
   evidence.
10. A repository script and regression tests validate the complete notebook contract, compile every code cell, exercise command-retry logging, and test safe ZIP extraction before packaging.

## Consequences

- Colab's unrelated preinstalled packages cannot invalidate the repository dependency check.
- A successful checkpoint is tied to one immutable commit and one isolated dependency graph.
- Notebook failures provide named command logs rather than an uncontextualised
  `CalledProcessError`.
- The checkpoint takes longer because it creates and provisions a clean environment.
- If online historical verification is deliberately disabled, the checkpoint is explicitly
  classified as partial and cannot serve as final acceptance evidence.

## Research impact

None. This decision changes checkpoint execution and evidence preservation only. The Stage 6.1
protocol, freeze revision, independent oracles, fairness mappings, EvidencePack Schema v0.2,
34-field Evidence Completeness denominator, and EC, TR, CD, CA, AR, SC, and EPG definitions remain
unchanged.
