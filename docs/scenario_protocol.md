# Controlled Scenario Replay Protocol

## Purpose

Scenario replay evaluates the artefact under predeclared evidence conditions without representing the scenarios as industrial case studies. The final study uses controlled scenario replays over real-format artifacts.

## Required scenario metadata

Each scenario must declare:

1. a stable scenario and case identifier;
2. purpose and threat narrative;
3. clock start `t_0`;
4. product, identity, vulnerability, supplier, local, asset, and mitigation context;
5. source artifacts and source hashes;
6. atomic claims with provenance;
7. ordered replay events;
8. active claims at each event;
9. the expected state at each event; and
10. the seeded conflict count.

Expected states and seeded conflicts must be fixed before replay.

## Replay procedure

1. Parse and validate the scenario YAML.
2. Establish `t_0` from `case_metadata.clock_start_time`.
3. Apply each event's evidence overrides to the previous evidence snapshot.
4. Activate the claims listed by the event.
5. Detect direct proposition conflicts and compute `C_t`.
6. Calculate `E_t`, `A_t`, `I_t`, `M_t`, and `U_t` using the v0.2.1 semantics; vulnerable-function execution contributes to `A_t`, while only an active traceable malicious-exploitation claim, KEV, or EPSS contributes numerically to `E_t`.
7. Calculate `delta_t_hours` from the event timestamp and `t_0`.
8. Apply the state rule in frozen precedence order.
9. Append a state-log and audit-log entry.
10. Generate the final EvidencePack, conflict report, and metrics output.

## Ghost-Logger acceptance criteria

The initial scenario is a fictional transitive-dependency case in which:

- a supplier assertion states `known_not_affected`;
- local telemetry later indicates vulnerable-function execution;
- the two active claims address the same product-affectedness proposition;
- one conflict is seeded and one conflict must be detected;
- `C_t` must become `true`; and
- the observed final state must be `Escalate`.

The first event may produce `Document No-Report` while evidence is reassuring and uncertainty is low. This is not a final legal determination; it is a time-stamped recommendation that can pivot when new evidence arrives.

## Remaining scenarios

- **False Comfort:** a reassuring third-party assertion is contradicted by local evidence.
- **Operational Outlier:** moderate technical severity is elevated by critical deployment context.
- **Rapid Pivot:** new evidence sharply changes uncertainty and state within the reporting clock.

A separate `Silent Transitive` label may be retained as the category name for Ghost-Logger; the scenario should not be double-counted as two independent evaluations.

## Baseline replay

For each scenario, a matched baseline analyst worksheet records whether each evidence source was consulted, whether provenance was preserved, whether conflicts were noticed, whether the clock was visible, and whether the final decision can be reconstructed. The baseline is a conventional un-orchestrated PSIRT process, not a claim about any named organization.


## Stage 1.5 implementation boundary

The current Ghost-Logger YAML remains a normalized scaffold. Stage 1.5 validates scoring semantics, configured deadline posture, authorization, submission separation, schema compatibility, and continuous regression. Stage 2 must replace normalized conclusions with evidence derived from real-format source artifacts before the scenario is used for final RQ4 evaluation.

Configured deadline results and human events are evaluated independently of `recommended_state`. Deadline-status entries must retain all six base `audit_log[]` fields required by EvidencePack v0.2.
