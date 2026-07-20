# Stage 5 Rapid Pivot Pilot

## Objective

Test the frozen uncertainty and clock-aware escalation mechanisms while preserving all earlier scenario behaviours and avoiding scenario-specific application code.

## Controlled temporal pair

Rapid Pivot and its early-resolution control use the same:

- CycloneDX SBOM, OSV-shaped record, KEV-shaped record, EPSS-shaped record, and CSAF/VEX document;
- asset and mitigation context;
- identity-confirmation and telemetry artefacts;
- target product, component, CVE, deployment identity, and scope;
- source timestamps;
- configured 24-hour and 72-hour deadline profile; and
- six replay-event timestamps.

The only treatment is when the four uncertainty-resolving artefacts become available to the orchestrator:

| Artefact group | Rapid Pivot | Early-resolution control |
|---|---:|---:|
| Identity confirmation, EPSS, VEX, reachability telemetry | T+20h | T+12h |

## Initial uncertainty

The SBOM contains one unique `session-router` version `3.1.4` component but omits its PURL. Before confirmation, the engine derives:

- `matching_method=fuzzy_name_version`;
- `gamma_id=0.4`;
- five missing uncertainty fields: EPSS, VEX, execution, reachability, and telemetry reference;
- `U_t=0.522222`;
- `E_t=0.85` from KEV; and
- `I_t=0.75` from high criticality and broad scope.

The frozen rule therefore recommends `Prepare`.

## Primary trajectory

| Time | Evidence condition | U_t | Recommendation |
|---|---|---:|---|
| T+2h | High exploitation/impact context; identity and local evidence incomplete | 0.522222 | Prepare |
| T+12h | Evidence gaps remain unresolved | 0.522222 | Prepare |
| T+18h | Prior state remains Prepare at the internal safeguard | 0.522222 | Escalate |
| T+20h | Exact CPE confirmation, EPSS, VEX, and reachability arrive | 0.15 | Report-Ready |
| T+22h | Human authorization and early-warning evidence | 0.15 | Report-Ready + authorized Report |
| T+72h | Verified mitigation and full-notification evidence | 0.15 | Report-Ready + authorized Report |

At T+18h the early-warning workflow deadline is `Due Soon`. This is recorded separately from the internal `tau_E` state safeguard.

## Temporal control

The control releases the same resolving evidence at T+12h. It moves from `Prepare` to `Report-Ready` before the T+18h event and does not trigger clock escalation. Its workflow deadline posture at every matched timestamp remains identical to the main replay.

## Metrics

The primary replay produces:

- `CA=1.0`, with one eligible safeguard opportunity and one escalation;
- `SC=1.0`;
- `TR=1.0`;
- `EC=1.0` in the final EvidencePack;
- deterministic generation of all six outputs.

The control has no eligible Prepare-at-or-after-18h opportunity, so `CA=null` with status `not_applicable`.

## Research interpretation

The paired replay demonstrates controlled conformance to the frozen uncertainty and elapsed-time rules. It does not establish that 18 hours is legally required, operationally optimal, or externally valid. The reporting-deadline profile remains an organisational replay configuration, not a legal applicability or awareness determination.

## Preserved boundaries

- EvidencePack Schema remains v0.2.
- The 34 Evidence Completeness fields remain unchanged.
- `tau_E` remains an internal safeguard and is not treated as a statutory deadline.
- Human authorization and submission evidence remain separate.
- All prior scenario trajectories remain regression-protected.
- Pilot outputs require preservation of the exact Git commit and Colab evidence-bundle hash before manuscript eligibility.
