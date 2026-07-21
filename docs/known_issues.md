# Known Issues and Deferred Quality Controls

## Open limitations

### KI-001 — Ghost-Logger evidence is fictional

Stage 2 uses representative machine-readable artefacts but a controlled fictional CVE, supplier, deployment, telemetry, and decision history. It verifies implementation behaviour and format ingestion, not industrial effectiveness or legal correctness. The four-scenario evaluation, matched baseline, expert plausibility review, and public historical replay remain pending.

### KI-002 — Identifier matching remains intentionally narrow

The pilot now demonstrates exact versioned PURL matching, a unique normalized name/version fallback, an OSV alias bridge, and explicit CPE-confirmed resolution. It does not implement general fuzzy ranking, ambiguous-candidate adjudication, CPE interval logic, package-ecosystem equivalence, or ontology-complete identity resolution. The artefact must not be described as solving general PURL/CPE identity matching.

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

## Stage 3 scope-model limitations

- The scope vocabulary is intentionally limited to product PURL, component PURL, CVE, product variant, deployment ID, and environment.
- A single CSAF model number is treated as a product-variant identifier; multi-valued model-number sets are retained in the source artefact but are not yet expanded into interval/set reasoning.
- Temporal staleness and expiry of otherwise applicable supplier assertions are not implemented in Stage 3.
- Geographic scope, serial-number ranges, CPE version intervals, and ontology-based equivalence remain deferred.
- Under the frozen v0.2 uncertainty equation, an explicit `not_applicable_scope_mismatch` VEX status is populated rather than missing, so the mismatch does not itself increase `U_t`; applicability falls back to identity-supported evidence instead. Any future uncertainty penalty for scope mismatch requires an explicit semantic decision rather than a silent scoring change.

## Stage 4 operational-impact limitations

- The NVD record is a controlled NVD API 2.0-shaped snapshot for a fictional CVE; it demonstrates parser and lineage behaviour rather than live-feed correctness.
- CVSS is retained as technical-severity context and is not an input to the frozen state rule. The pilot must not imply that CVSS determines operational impact or legal reportability.
- The Operational Outlier pair tests one configured impact contrast. The `I_t` thresholds and criticality/scope mappings remain design parameters requiring sensitivity analysis and expert plausibility review before evaluation freeze.
- The control is matched within the artefact's declared fields, but it is not a real-world causal experiment or population-level estimate.

## Stage 5 uncertainty and clock limitations

- The uncertainty score remains the frozen missingness-plus-identity-confidence equation. It does not numerically model evidence age, telemetry coverage, analyst disagreement, or source reliability beyond the declared fields.
- The `fuzzy_name_version` path requires exactly one normalized name/version candidate; ambiguous candidates fail closed rather than being ranked.
- The CPE-confirmation artefact is controlled fictional evidence and demonstrates validation flow, not general vendor-identity truth.
- `tau_E=18h` is an internal design safeguard. It is not a statutory deadline, a legal-awareness determination, or evidence that 18 hours is empirically optimal.
- The early-resolution control isolates evidence-release timing within the declared model, but it is not a real-world causal experiment.

## Stage 5.5 historical-replay limitations

- Public chronology cannot establish organisation-local reachability, execution, impact, mitigation, authorization, submission, or legal applicability. The public-only replay therefore does not generate an EvidencePack.
- Date-only publications use conservative end-of-day UTC availability. This avoids premature evidence release but reduces within-day temporal precision.
- The reference deployment is synthetic and must not be described as a real Palo Alto Networks customer or incident case study.
- The 2024-04-15 EPSS value is a provisional secondary reconstruction. It blocks frozen-evaluation and manuscript eligibility until directly verified from a FIRST historical API response or daily archive; alternatively, the value must be removed from the eligible replay.
- Research-normalized NVD, KEV, advisory, OSV, CycloneDX, and CSAF-shaped extracts preserve provenance but are not substitutes for complete official archive exports or official vendor CSAF publication.
