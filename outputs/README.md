# Generated Outputs

The CLI writes deterministic scenario products into four directories:

- `evidence_packs/` — EvidencePack v0.2 JSON.
- `state_logs/` — ordered CSV state transitions.
- `conflict_reports/` — detected proposition conflicts and source-linked claims.
- `metrics/` — EC, TR, CD, CA, AR, SC, and EPG results.

Generated files are ignored by Git by default. For a paper release, publish a tagged evaluation snapshot or attach the outputs to the research archive with commit and source-artifact hashes.
