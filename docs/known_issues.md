# Known Issues and Deferred Quality Controls

## Open limitations

### KI-001 — Ghost-Logger evidence is fictional

Stage 2 uses representative machine-readable artefacts but a controlled fictional CVE, supplier, deployment, telemetry, and decision history. It verifies implementation behaviour and format ingestion, not industrial effectiveness or legal correctness. The four-scenario evaluation, matched baseline, expert plausibility review, and public historical replay remain pending.

### KI-002 — Identifier matching is intentionally narrow

The pilot demonstrates an exact versioned PURL match and OSV alias bridge. Fuzzy, CPE, ambiguous-candidate, and multi-ecosystem resolution remain later evaluation work. The artefact must not be described as solving general PURL/CPE identity matching.

### KI-003 — Conflict semantics are scoped but not ontology-complete

Stage 2 compares exact propositions and serialized scopes. It distinguishes sequential same-class observations from simultaneous cross-class contradictions, but does not yet implement a comprehensive proposition ontology, interval algebra, or semantic subsumption.

### KI-004 — Full standards conformance validation is incomplete

The committed CycloneDX and CSAF documents are structurally parsed and checked by repository tests, but the pipeline does not yet run the complete official CycloneDX and OASIS CSAF schema suites. Add official-schema validation before the evaluation freeze.

### KI-005 — GitHub Actions use major tags rather than immutable SHAs

Dependabot and actionlint reduce version-drift risk, but immutable action SHA pinning remains required for the archival release.

### KI-006 — Mutation and security testing remain deferred

Property tests and branch coverage are active. Mutation testing, CodeQL, secret scanning, and dedicated dependency vulnerability scanning should be added after the Stage 2 APIs stabilise and before the final public release.

### KI-007 — Execution Latency is not yet instrumented

EL is defined but not emitted by the CLI. Functional development can proceed, but latency and scale results are mandatory before evaluation-results freeze.

### KI-008 — Pilot paper assets are not final results

The Stage 2 figures and tables are generated from a local export build whose Git commit is not recorded. They must be regenerated from a tagged GitHub commit and independently reproduced in Colab before manuscript use.
