# Stage 6.1 Evaluation Oracles

These event-level oracles are frozen before the final matched evaluation. They are
independent of the baseline and artefact outputs and therefore cannot be derived from
one of the systems under evaluation.

- `state_oracle_v0.1.yaml` preserves the controlled expected state, authorization, and
  deadline posture at every event.
- `conflict_oracle_v0.1.yaml` identifies the event-level conflict ground truth used for
  precision and recall.
- `clock_opportunity_oracle_v0.1.yaml` identifies automatic `tau_E` opportunities while
  keeping human clock awareness as a separately recorded baseline observation.

Changing an oracle after execution requires a new version, ADR, protocol freeze, and full rerun.
