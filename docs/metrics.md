# Evaluation Metrics

**EvidencePack schema:** v0.2  
**Semantic clarification:** v0.2.1

The seven effectiveness metrics below remain frozen. Their equations, denominators, and counting rules must not be changed without explicit approval. Execution Latency is supplemental and does not alter the locked metric set or the 34-field Evidence Completeness denominator.

## 1. Evidence Completeness

```text
EC = |F_pop intersect F_req| / |F_req|
|F_req| = 34
```

The population rules are documented in `schema.md`. Boolean `false` counts as populated.

## 2. Traceability Ratio

A claim is traceable only if it contains `source_artifact_id`, `source_uri`, `source_hash`, `timestamp`, and `confidence`.

```text
TR = sum(traceable(c) for c in C_claims) / |C_claims|
```

## 3. Conflict Detection

```text
CD = |K_detected| / |K_seeded|
```

The controlled-scenario protocol must declare seeded conflicts before replay. The conflict report must identify the active claim pair or claim set that produced each detection.

## 4. Clock-Aware Escalation

```text
CA = |T_esc| / |T_near|
```

`T_near` contains replay opportunities where a prior evidential state is `Prepare` and `delta_t >= tau_E`. `T_esc` contains those opportunities where the observed recommended state is `Escalate`.

CA evaluates the internal `tau_E` safeguard within `R_t`; it is not a metric of configured deadline status `D_(k,t)` or legal compliance.

If `|T_near| = 0`, the serialized metric value is `null` and its status is `not_applicable`; the formula itself is unchanged.

## 5. Audit Reconstructability

```text
AR = |D_recon| / |D_total|
```

A decision is reconstructable when the audit entry contains a stable event identifier, timestamp, actor, action, relevant input references, and an output hash or state.

## 6. State Correctness

```text
SC = |{s_i : s_i_observed = s_i_expected}| / |S_expected|
```

Expected evidential states are declared before replay in the scenario protocol. SC measures conformance with the predeclared prototype oracle; it is not external proof that the state is legally correct.

## 7. Evidence-Pack Generation

```text
EPG = 1  if evidence pack, state log, and conflict report are generated
      0  otherwise
```

## 8. Baseline comparison

The same applicable locked metrics are computed for the orchestration artefact and for the matched un-orchestrated PSIRT baseline.

The baseline analyst receives the same evidence and may use predeclared ordinary inspection tools, including `jq`, `grep`, text editors, spreadsheet software, and JSON or CSV viewers. The analyst does not receive the generated claims, automated conflict report, expected states, or the prototype output.

Identity uncertainty is reported alongside the frozen metric set as the observed `gamma_id` and `U_t`, rather than introduced as an unapproved additional effectiveness metric.

---

## 9. Supplemental metric: Execution Latency

Execution Latency measures implementation feasibility. It is reported independently of the seven locked effectiveness metrics and independently of human Time to Decision.

### 9.1 Offline Execution Latency

\[
\boxed{EL_{\mathrm{offline}}=t_{\mathrm{outputs\_committed}}-t_{\mathrm{ingestion\_started}}}
\]

This measures deterministic local validation, parsing, identity resolution, claim generation, conflict evaluation, scoring, state and deadline evaluation, and output emission using cached snapshots.

### 9.2 Acquisition Latency

\[
\boxed{EL_{\mathrm{acquisition}}=t_{\mathrm{cache\_completed}}-t_{\mathrm{fetch\_started}}}
\]

This measures remote acquisition during cold-cache retrieval of sources such as OSV, KEV, or EPSS.

### 9.3 Live End-to-End Latency

\[
\boxed{EL_{\mathrm{live}}=t_{\mathrm{outputs\_committed}}-t_{\mathrm{fetch\_started}}}
\]

`EL_offline + EL_acquisition` equals `EL_live` only when acquisition and local processing are strictly sequential. Direct wall-clock measurement remains authoritative for concurrent or overlapping execution.

### 9.4 Human Time to Decision

Human workflow duration may be reported separately as:

\[
TTD=t_{\mathrm{decision\_recorded}}-t_{\mathrm{evidence\_released}}.
\]

TTD is contextual workflow evidence, not an eighth locked effectiveness metric. Machine latency must not be presented as equivalent to human review or regulatory decision time.

## 10. Instrumentation and benchmarking protocol

- use `time.perf_counter_ns()` for elapsed durations;
- reserve UTC timestamps for audit and provenance events;
- execute at least 30 recorded runs per scenario;
- discard one initial warm-up run;
- report median, minimum, maximum, and 95th percentile;
- report Python version, CPU, memory, operating environment, cache condition, input bytes, component count, claim count, and source-artifact count;
- separate cached deterministic processing from live network acquisition.

## 11. Controlled scale-testing matrix

| Fixture ID | Components | Maximum depth | Claims | Seeded conflicts | Input size |
|---|---:|---:|---:|---:|---|
| `S100` | 100 | 10 | 50 | 2 | Recorded at generation |
| `S1K` | 1,000 | 10 | 500 | 10 | Recorded at generation |
| `S10K` | 10,000 | 20 | 5,000 | 50 | Recorded at generation |

Every synthetic scale fixture must freeze and record:

- random seed;
- graph-generation algorithm;
- branching factor;
- vulnerability count;
- transitive-component proportion;
- source-artifact count;
- claim-to-component distribution;
- conflict-placement algorithm; and
- identity-match distribution.

The default identity-match distribution for a benchmark series must be declared explicitly, for example:

```yaml
exact_versioned_purl: 0.60
osv_ecosystem_name_version: 0.20
confirmed_cpe: 0.10
fuzzy_name_version: 0.07
name_only: 0.03
```

A benchmark series must use the same distribution across sizes unless the experiment explicitly studies identity-resolution effects.

## 12. Storage rule

Execution Latency and benchmark results are written to `outputs/metrics/*.json` or dedicated benchmark sidecars. They are not added to the EvidencePack v0.2 mandatory fields. Making EL a required EvidencePack field would require a structural schema version change.
