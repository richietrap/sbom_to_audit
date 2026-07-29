# Stage 6.1 Metric Fairness Controls

## Locked metrics

EC, TR, CD, CA, AR, SC, and EPG remain exactly as defined in `docs/metrics.md`.

## Supplemental controls

- **Common-field completeness:** shared evidence and decision fields only; it does not replace
  the 34-field EC denominator.
- **Partial lineage:** source ID, URI, hash, and timestamp without confidence.
- **Conflict precision:** exact event detections against an independent oracle.
- **Equivalent bundle generation:** case, decision, conflict, and source records for each
  workflow; it does not replace EPG.
- **Source access:** distinct artifact IDs are the comparable unit. Repeated human accesses are
  reported separately.
- **Human Time to Decision:** measured from review start to decision record; machine latency
  remains separate.
- **Clock interpretation:** CA is retained. The automatic `tau_E` mechanism is an ablation;
  human awareness is recorded independently.

Blank and unavailable values are never converted to favourable defaults. Boolean false and
numeric zero remain populated values under the locked rules.
