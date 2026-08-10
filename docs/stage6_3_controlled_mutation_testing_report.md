# Stage 6.3 Controlled Mutation Testing Report

## Status

`CANDIDATE_NOT_FROZEN`; not manuscript eligible.

## Parent checkpoint

- Stage 6.2 Git commit: `36cb40fed9be39a19da25df70bb524c2cc05e316`
- Stage 6.2 Colab evidence SHA-256:
  `01b184fb95dcec987cd599e2a50dc1ad6027b8d0dfce2d0d9af2fdf20090d3f1`

## Scope

Stage 6.3 registers 26 first-order mutants across seven logic families:
authorisation, conflict, evidence semantics, identity and uncertainty, metrics, temporal
decision logic, and traceability and source integrity. Each mutant changes one declared source
expression in a disposable repository copy. The accepted source tree is restored after each
run.

## Candidate observations

The baseline phase, which uses only tests predating Stage 6.3, killed 18 mutants and left eight
survivors. Eight targeted safety tests were then registered to exercise the exposed gaps. In
the strengthened phase, all 26 registered mutants were killed, with no invalid or timed-out
mutants.

These values are bounded candidate observations. They do not establish exhaustive mutation
coverage, universal test adequacy, legal correctness, industrial effectiveness, or the absence
of unregistered defects. They must not enter the final manuscript as frozen results until the
exact commit passes GitHub and Colab and the final evaluation freeze approves the associated
claim and assets.

## Reproducibility outputs

- `evaluation/stage6_3_candidate/stage6_3_mutant_registry.csv`
- `evaluation/stage6_3_candidate/stage6_3_mutation_results.csv`
- `evaluation/stage6_3_candidate/stage6_3_family_summary.csv`
- `evaluation/stage6_3_candidate/stage6_3_surviving_mutants.csv`
- `evaluation/stage6_3_candidate/stage6_3_mutation_summary.json`
- `evaluation/stage6_3_candidate/stage6_3_output_manifest.json`

Candidate paper assets are generated from those files and carry preserved source and output
hashes.

## Limitations

- The mutation registry is deliberately bounded and first order.
- Exact-text mutations require maintenance after source refactoring.
- Targeted test nodes are not a substitute for the complete repository regression suite.
- Equivalent mutants are not declared automatically.
- Mutation detection evaluates the verification system, not whether prototype thresholds or
  decision rules are legally or empirically optimal.
