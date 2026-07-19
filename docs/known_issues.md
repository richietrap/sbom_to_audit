# Known Issues and Deferred Quality Controls

## Open limitations

### KI-001 — Real-format source files are not yet present

Ghost-Logger still references future CycloneDX, CSAF/VEX, and telemetry files. The
repository validator reports these as warnings. Stage 2 must create, hash, validate, and
ingest them, after which strict source validation becomes mandatory.

### KI-002 — GitHub Actions use major tags rather than immutable commit SHAs

`actions/checkout@v6` and `actions/setup-python@v6` are valid, but major tags can move.
Dependabot monitors them and actionlint validates syntax. Immutable SHA pinning remains
recommended before the final archival release, after the exact upstream SHAs are
independently verified.

### KI-003 — Mutation testing is not yet enforced

Property tests and branch coverage are implemented, but mutation testing is deferred
until the Stage 2 parser and source-registry APIs stabilise. The current risk is that
some weak assertions may not detect semantically inverted code.

### KI-004 — Security scanning is partial

Dependency monitoring is enabled, but CodeQL, secret scanning, and a dedicated dependency
vulnerability scanner are not yet configured. The repository is public and contains no
secrets by design. These controls should be added before external contributors or live
credentials are introduced.

### KI-005 — Performance benchmarking remains pending

Execution Latency is defined but not yet instrumented. This does not block Stage 2
functional development, but it must be completed before the evaluation-results freeze.
