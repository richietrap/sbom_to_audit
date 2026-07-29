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

## Stage 5 Clock-Aware Escalation interpretation

Rapid Pivot creates one applicable CA opportunity: the prior state is `Prepare` and the matched event occurs at `delta_t=18h`. The observed state is `Escalate`, so the controlled pilot value is `CA=1.0`. Its early-resolution control has no event satisfying the denominator condition because the prior state at T+18h is `Report-Ready`; its serialized value therefore remains `null` with status `not_applicable`, not `0.0`.

The metric evaluates conformance to the configured internal safeguard. It does not validate a statutory deadline, legal awareness, or the empirical optimality of the 18-hour parameter.

## Stage 6 matched baseline interpretation

The Stage 6 baseline is defined in `evaluation/baseline_protocol_v0.1.yaml`. It shares source validation and format parsing with the artefact so that parser quality is not a confound, but it does not use the orchestration claim graph, scope engine, numerical evidence variables, conflict lifecycle, `tau_E` safeguard, or EvidencePack generation.

The locked metrics remain unchanged. Two supplemental measures are reported:

- **partial traceability ratio:** the proportion of the five traceability fields populated across baseline observations. It contextualizes strict `TR` without replacing it;
- **conflict precision:** true seeded conflict episodes divided by all detected episodes across the controlled suite. This exposes scope-blind false positives that conflict recall alone cannot show.

A cumulative source-review operation count is also reported as a deterministic process proxy. It must not be interpreted as analyst time or cognitive workload.

## Stage 6.1 fairness controls

The seven effectiveness metrics above remain unchanged. Stage 6.1 adds only supplemental controls:

- **Common-Field Completeness:** completeness over the frozen field subset both workflows are reasonably expected to record. It contextualizes EC and does not change its 34-field denominator.
- **Partial Lineage Ratio:** populated provenance elements divided by five per observation. Strict TR still requires all five elements, including confidence.
- **Conflict Precision:** event-level true positives divided by all detected conflict events using the independent frozen conflict oracle.
- **Equivalent Record-Bundle Generation:** whether each workflow generated its frozen functionally equivalent case, decision-history, conflict-history, and source-register records. It does not change EPG.
- **Source-Access Accounting:** distinct source artefacts and total access events are calculated using the same units for both workflows.
- **Human Time to Decision:** elapsed analyst review minutes recorded separately from machine execution latency.
- **Automatic Clock-Safeguard Ablation:** the configured `tau_E` mechanism is evaluated separately from claims about human clock awareness.
