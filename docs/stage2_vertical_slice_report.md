# Stage 2 Vertical-Slice Report

**Version:** 0.2.3  
**Status:** PILOT — not yet eligible as final paper evidence  
**Scenario:** Silent Transitive / Ghost-Logger  
**Run ID:** `GL-STAGE2-PILOT-001`

## Objective

Stage 2 replaces the earlier normalized-YAML demonstration with a real-format vertical slice. The replay now derives product identity, vulnerability intelligence, supplier assertions, local evidence, asset context, mitigation context, conflicts, temporal states, human authorization, deadline satisfaction, and audit outputs from committed source artefacts.

## Source bundle

The controlled replay registers 15 artefacts across CycloneDX, CSAF/VEX, OSV-shaped, KEV-shaped, EPSS-shaped, JSONL telemetry, YAML asset and mitigation records, conflict-resolution records, human authorization, and milestone-completion evidence. The source registry verifies path confinement, file presence, parser assignment, media type, size, and computed SHA-256.

## Temporal result

| Time | Recommended state | Authorization | Principal reason |
|---|---|---|---|
| T+2h | Document No-Report | null | Supplier assertion and no local execution evidence |
| T+10h | Escalate | null | Active supplier/local affectedness conflict |
| T+14h | Report-Ready | null | Applicability confirmed and conflict formally resolved |
| T+20h | Report-Ready | Report | Explicit human authorization and early-warning completion evidence |
| T+72h | Report-Ready | Report | Mitigation and full-notification evidence added without rewriting history |

Final evidence variables are `E_t=0.85`, `A_t=1.0`, `I_t=0.75`, `M_t=1.0`, `U_t=0.0`, and `C_t=false` after scoped conflict resolution.

## Generated outputs

- EvidencePack v0.2 JSON;
- state-transition CSV;
- conflict-report JSON;
- metric sidecar JSON;
- verified source manifest JSON; and
- append-only audit-ledger JSONL.

## Pilot metrics

The pilot reports `EC=1.0`, `TR=1.0`, `CD=1.0`, `AR=1.0`, `SC=1.0`, and `EPG=1`. `CA` is not applicable because the scenario does not contain a Prepare event that reaches the 18-hour safeguard. Supplemental checks for source integrity, authorization correctness, and deadline-posture correctness are `1.0`.

These results demonstrate implementation conformance within the controlled replay. They do not establish legal correctness, industrial effectiveness, threshold validity, or external generalisability.

## Quality evidence

- 62 automated tests passed in the Stage 2 build;
- branch-aware coverage exceeded the 70% ratchet;
- strict source validation passed;
- schema version remained `0.2`;
- the EC denominator remained 34;
- all six generated outputs were byte-identical across deterministic double replay; and
- lint, formatting, static typing, spelling, YAML, dependency, compilation, and release checks passed.

## Paper-facing pilot assets

The data-driven asset pipeline currently produces:

- F01 — prototype evidence pipeline;
- F02 — Ghost-Logger temporal evidence trajectory;
- T01 — source artefact inventory; and
- T02 — event replay table.

Every asset is linked to the pilot run, source-data hashes, generation-script hash, output hash, and `PILOT/NOT_ELIGIBLE` status in `paper_assets/figure_table_register.csv`.

## Remaining work before evaluation freeze

1. rerun the vertical slice from an exact Git commit in GitHub and Colab;
2. validate CycloneDX and CSAF inputs against complete official schemas;
3. add Ghost-Logger negative controls and perturbations;
4. generalise and test the engine with False Comfort;
5. implement Operational Outlier and Rapid Pivot;
6. instrument Execution Latency and scale fixtures;
7. conduct the matched manual-assisted PSIRT baseline;
8. conduct formative expert plausibility review where available; and
9. complete the CVE-2024-3400 retrospective public replay.
