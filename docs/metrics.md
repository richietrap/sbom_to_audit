# Evaluation Metrics

These definitions are frozen for EvidencePack v0.2 evaluation.

## Evidence Completeness

```text
EC = |F_pop intersect F_req| / |F_req|
|F_req| = 34
```

The population rules are documented in `schema.md`. Boolean `false` counts as populated.

## Traceability Ratio

A claim is traceable only if it contains `source_artifact_id`, `source_uri`, `source_hash`, `timestamp`, and `confidence`.

```text
TR = sum(traceable(c) for c in C_claims) / |C_claims|
```

## Conflict Detection

```text
CD = |K_detected| / |K_seeded|
```

The controlled scenario protocol must declare seeded conflicts before replay. The conflict report must identify the active claim pair or claim set that produced each detection.

## Clock-Aware Escalation

```text
CA = |T_esc| / |T_near|
```

`T_near` contains replay opportunities where a prior state is `Prepare` and `delta_t >= tau_E`. `T_esc` contains those opportunities where the observed state is `Escalate`. If `|T_near| = 0`, the serialized metric value is `null` and its status is `not_applicable`; the formula itself is unchanged.

## Audit Reconstructability

```text
AR = |D_recon| / |D_total|
```

A decision is reconstructable when the audit entry contains a stable event identifier, timestamp, actor, action, relevant input references, and an output hash or state.

## State Correctness

```text
SC = |{s_i : s_i_observed = s_i_expected}| / |S_expected|
```

Expected states are declared before replay in the scenario protocol.

## Evidence-Pack Generation

```text
EPG = 1  if evidence pack, state log, and conflict report are generated
      0  otherwise
```

## Baseline comparison

The same applicable metrics are computed for the orchestration artefact and for the un-orchestrated PSIRT baseline. Identity uncertainty is reported alongside the frozen metric set as the observed `gamma_id` and `U_t`, rather than introduced as an unapproved eighth formal metric.
