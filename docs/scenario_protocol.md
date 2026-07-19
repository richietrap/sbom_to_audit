# Controlled Scenario Replay Protocol

**Semantic version:** v0.2.1  
**Schema version:** EvidencePack v0.2

## 1. Purpose

Scenario replay evaluates the artefact under predeclared evidence conditions without representing the scenarios as industrial case studies. The final study uses **controlled scenario replays over real-format artifacts**.

The scenario definition configures evidence release and expected behaviour. It must not inject normalized answers that the prototype is expected to derive.

## 2. Scenario-definition boundary

A final evaluation scenario may contain:

- stable scenario and case identifiers;
- a fictional or hybrid historical-synthetic narrative;
- `t_0` as an internal awareness proxy;
- relative or absolute evidence-release times;
- paths to real-format input artefacts;
- a configured deadline profile;
- prototype parameters;
- predeclared seeded-conflict descriptions;
- expected evidential-state, deadline, authorization, and submission oracles; and
- explicit human authorization or submission events where the scenario requires them.

A final evaluation scenario must not contain:

- precomputed `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, or `C_t` values;
- pre-generated normalized claims;
- trusted source hashes that the source registry does not recompute;
- derived identity matches;
- parser outputs;
- generated state rationale; or
- a final EvidencePack embedded as scenario input.

The current Ghost-Logger YAML is a scaffold fixture and must be replaced or migrated before final v0.2.1 evaluation.

## 3. Required real-format source bundle

Each base scenario should provide, as applicable:

1. CycloneDX JSON SBOM;
2. CSAF/VEX JSON supplier assertion;
3. cached OSV response;
4. dated CISA KEV snapshot or scenario-specific extract preserving source metadata;
5. dated EPSS response;
6. telemetry in JSONL, JSON, or CSV;
7. asset-context JSON or YAML;
8. mitigation-context JSON or YAML; and
9. explicit human-decision or milestone-completion records where needed.

Every source must be registered, validated, timestamped, and hashed by the prototype.

## 4. Predeclared oracle

Expected outcomes must be frozen before final replay. Each event oracle separates four concepts:

```yaml
expected:
  recommended_state: Report-Ready
  deadline_posture:
    early_warning:
      status: Overdue
    full_notification:
      status: Breach Imminent
  authorized_state: null
  submission_evidence:
    early_warning: null
    full_notification: null
```

- `recommended_state` evaluates `R_t`.
- `deadline_posture` evaluates the configured `D_(k,t)` milestones.
- `authorized_state` records expected human authorization.
- `submission_evidence` records whether a milestone should be considered satisfied.

State Correctness uses only the predeclared evidential `recommended_state` values unless a separate deadline-conformance result is explicitly reported.

## 5. Replay procedure

1. Parse and validate the scenario configuration.
2. Establish `t_0` from the recorded internal awareness proxy.
3. Register every referenced source artefact.
4. Validate the format and compute the source hash.
5. Release source artefacts according to the ordered event timeline.
6. Parse the newly available evidence through format-specific parsers.
7. resolve product, component, version, and vulnerability identity;
8. generate normalized, scoped, traceable claims;
9. detect active claim conflicts and compute `C_t`;
10. compute `E_t`, `A_t`, `I_t`, `M_t`, and `U_t` using the frozen semantics;
11. calculate `delta_t_hours` from the event timestamp and `t_0`;
12. apply the evidential state rule in frozen precedence order;
13. evaluate every enabled deadline milestone independently;
14. apply explicit human authorization and milestone-satisfaction events without conflating them;
15. append state, deadline, authorization, source, and audit records; and
16. generate the EvidencePack, state log, conflict report, source manifest, and metrics sidecar.

## 6. Ghost-Logger target trajectory

Ghost-Logger is the Silent Transitive scenario. The complete target replay contains:

| Time | Evidence purpose | Expected posture |
|---|---|---|
| T+2h | Transitive component present; supplier says not affected; no local execution | `Document No-Report` or `Monitor`, as frozen in the final oracle |
| T+10h | Local vulnerable-function execution contradicts the supplier assertion | `Escalate`, active conflict |
| T+14h | Internal reproduction confirms applicability and resolves the scoped affectedness conflict | `Report-Ready` when all thresholds are met |
| T+20h | Explicit human review event | `authorized_state=Report` only if the scenario oracle specifies it |
| T+72h | Mitigation, deployment scope, and milestone-completion evidence are added | prior history retained; payload enriched |

Vulnerable-function execution affects `A_t`; it does not automatically set `E_t=1.0`. Exploitation evidence must come from a correctly scoped malicious-exploitation claim, KEV, EPSS, or another explicitly versioned contributor.

## 7. Remaining scenarios

- **False Comfort:** valid but stale, wrongly scoped, or version-mismatched reassurance is challenged by local evidence; the scenario may resolve to a defensible human-authorized no-report outcome.
- **Operational Outlier:** moderate technical severity is elevated by critical deployment context, testing the influence of `I_t` without requiring a supplier/local conflict.
- **Rapid Pivot:** unresolved evidence remains in `Prepare`, exercises the internal `tau_E` safeguard, and later pivots after new evidence.

Ghost-Logger must not be counted separately from Silent Transitive.

Every base scenario requires at least one negative-control variant in which a small, predeclared evidence change produces a different expected outcome.

## 8. Deadline-profile requirements

Each monitored milestone defines:

- milestone ID;
- `tau_k` due time;
- due-soon lead `w_k`;
- breach-imminent lead `b_k`;
- profile-enable flag `Q_(k,t)`;
- clock basis;
- expected satisfaction evidence, where applicable.

The configured profile is an evaluation and workflow aid. It does not establish legal applicability or legal awareness.

## 9. Baseline replay

The baseline analyst receives the same source artefacts, release timeline, and task. The analyst may use predeclared ordinary inspection tools such as `jq`, `grep`, text editors, spreadsheet software, and JSON or CSV viewers.

The analyst must not receive:

- prototype-generated claims;
- automated conflict reports;
- expected scenario states;
- prototype-generated packs; or
- custom orchestration scripts implementing the experimental intervention.

The baseline protocol records tools, commands, evidence consulted, start and finish times, provenance retained, conflicts noticed, deadline posture, rationale, and reconstructability.

## 10. Freeze and change control

Final scenario oracles must be committed before final evaluation. Any change requires:

- a dated rationale;
- an ADR or scenario change record;
- an updated golden fixture;
- an impact assessment on reported results; and
- preservation of the prior version.
