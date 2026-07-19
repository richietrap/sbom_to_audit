# Stage 3 Scope Generalisation and False Comfort Pilot

## Objective

Generalise Stage 2's claim and conflict handling without changing EvidencePack Schema v0.2, then implement the False Comfort scenario and a matched negative control using the same application code.

## Implemented mechanism

The artefact now normalises identity and deployment scope, determines whether a supplier assertion covers the active deployment, and detects contradictions only when claim scopes overlap.

### False Comfort trajectory

| Time | Evidence condition | Expected recommendation |
|---|---|---|
| T+2h | Supplier says `known_not_affected` for `standard-profile`; deployed variant is `legacy-plugin-profile` | Monitor |
| T+8h | Local telemetry confirms reachability in the legacy deployment | Report-Ready |
| T+12h | Human authorization and early-warning completion evidence | Report-Ready + authorized Report |
| T+72h | Verified mitigation and full-notification evidence | Report-Ready + authorized Report |

### Negative control

The control uses the same SBOM, vulnerability intelligence, and supplier VEX but a deployment matching `standard-profile`. With no local reachability or execution, the VEX assertion is applied and the recommendation is `Document No-Report`.

## Research interpretation

The paired replay tests mechanism selectivity: the artefact should neither trust a narrow assurance outside its scope nor reject the same assurance when its scope matches. The result is controlled rule conformance, not evidence of industrial decision accuracy.

## Preserved boundaries

- EvidencePack Schema remains v0.2.
- The 34 Evidence Completeness fields remain unchanged.
- Human authorization remains separate from recommendation.
- The scenario YAML contains source releases and expected oracles, not precomputed scores, claims, hashes, or conflict outputs.
- Ghost-Logger's intentional conflict and corrected resolution lifecycle remain unchanged.
