# Generated Outputs

The CLI writes deterministic replay products into six directories:

- `evidence_packs/` — EvidencePack v0.2 JSON;
- `state_logs/` — ordered CSV state transitions;
- `conflict_reports/` — detected and historically preserved conflicts;
- `metrics/` — locked and supplemental evaluation measures;
- `source_manifests/` — parser, validation, file-size, path, and computed-hash records;
- `audit_ledgers/` — append-only JSONL audit events.

`validation/` is reserved for machine-readable release and checkpoint reports.

Generated files are ignored by Git. Frozen evaluation outputs should be preserved in a tagged research archive together with the exact Git commit, source-manifest hash, output-manifest hash, and environment record.
