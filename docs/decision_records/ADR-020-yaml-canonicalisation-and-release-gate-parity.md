# ADR-020: YAML Canonicalisation and Release-Gate Parity

- **Status:** Accepted for Stage 6.1.4
- **Date:** 2026-07-29
- **Version:** 0.6.1.4

## Context

Stage 6.1.3 passed Ruff lint, Ruff formatting, Mypy, and Codespell in GitHub Actions, but Yamllint rejected one workflow and sixteen Stage 6.1 YAML files. The YAML documents were syntactically valid and loaded successfully through PyYAML, but several sequences used indentless serialization and the regression workflow ended with an extra blank line. The release package had therefore passed semantic parsing while failing the repository's declared presentation and quality contract.

The repeated corrective releases also showed that a single combined `Run static quality checks` step obscured which command failed until the complete log was expanded. This delayed diagnosis and weakened the confidence that packaging evidence corresponded to the final repository tree.

No manual baseline execution has begun. Consequently, the Stage 6.1 pre-execution protocol may receive a byte-only canonicalisation correction provided that parsed semantic equivalence is proved, the freeze revision is refreshed, and the change is disclosed before any evaluation data are collected.

## Decision

1. Release the correction as **Stage 6.1.4**, package version **0.6.1.4**.
2. Canonicalise sequence indentation in every YAML file reported by Yamllint and remove the trailing blank line from `.github/workflows/tests.yml`.
3. Compare each affected YAML or workflow document before and after correction using parsed YAML objects. Any semantic mismatch blocks the release.
4. Preserve protocol version `0.2`, oracle version `0.1`, mapping version `0.1`, EvidencePack Schema v0.2, the 34-field EC denominator, and all locked metrics.
5. Refresh the byte-level pre-execution freeze as `STAGE6-1-PRE-EXECUTION-FREEZE-002`. The original freeze remains available in prior Git history; the revised freeze is the only candidate permitted for the future manual run.
6. Split Ruff lint, Ruff formatting, Mypy, Codespell, and Yamllint into separate GitHub Actions steps. No combined step may hide the identity of a failing static gate.
7. Treat quality evidence as valid only for the exact final repository tree. Packaging must occur after every declared static gate, regression job, freeze check, and repository validator has passed.
8. Preserve all previous corrective packages as development history; only Stage 6.1.4 or later may proceed to the immutable Colab checkpoint and manual execution.

## Consequences

- BUG-021 records the YAML-quality and workflow-empty-line failure.
- Stage 6.1.4 supersedes Stage 6.1.3 as the current pre-execution candidate.
- The freeze hashes change because file bytes change, but a semantic-equivalence report demonstrates that protocol, oracle, mapping, and release-manifest values do not.
- GitHub Actions will identify each static-quality failure independently.
- A green GitHub quality workflow and exact-commit Colab reproduction remain mandatory before the baseline packet is used by an analyst.

## Affected files

- `.github/workflows/quality.yml`
- `.github/workflows/tests.yml`
- `data/baseline_instructions/allowed_tools.yaml`
- all seven `data/baseline_release_packets/*/release_manifest.yaml` files
- `evaluation/baseline_protocol_v0.2.yaml`
- all Stage 6.1 oracle and fairness-mapping YAML files
- `evaluation/freeze/stage6_1_protocol_freeze.json`
- `evaluation/freeze/stage6_1_4_yaml_semantic_equivalence.json`
- release-version markers, changelog, manifest, bug register, quality documentation, tests, and Colab checkpoint

## Required verification

- all affected YAML files parse before and after correction to equal Python objects;
- no affected file contains trailing whitespace or an excess blank line at EOF;
- Yamllint passes the exact CI scope;
- actionlint passes both workflows;
- Ruff lint and formatter, Mypy, Codespell, tests, branch coverage, repository validation, and freeze verification pass;
- Stage 6.1 protocol, oracle, mapping, scenario, schema, and metric semantics remain unchanged; and
- the exact Git commit is reproduced through the Stage 6.1.4 Colab checkpoint before manual execution.
