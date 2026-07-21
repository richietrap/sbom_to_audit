# Controlled Scenario Replay Protocol

## Purpose

Scenario replay evaluates the artefact under predeclared evidence conditions without representing controlled scenarios as industrial case studies. Stage 2 uses controlled fictional events over committed, machine-readable security artefacts.

## Stage 2 scenario contract

A scenario YAML is a replay manifest, not a container for normalized answers. It must declare:

1. stable scenario and case identifiers;
2. purpose, classification, and evaluation status;
3. `clock_start_time` and its internal-awareness-proxy basis;
4. target product PURL, component PURL, CVE, and CSAF product identifier;
5. configured deadline milestones;
6. a source catalog containing artefact IDs, types, repository paths, and source timestamps;
7. ordered replay events that release source artefacts;
8. expected recommended state, authorization state, and deadline posture; and
9. the seeded conflict count.

The scenario must not embed:

- precomputed `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, or `C_t` values;
- normalized claims;
- source hashes;
- resolved identity-confidence values;
- conflict results; or
- final decision rationale.

## Replay procedure

1. Load the source catalog.
2. confine every source path to the repository root;
3. validate each source with its designated parser;
4. calculate SHA-256 directly from the committed file;
5. release artefacts according to the event timeline;
6. derive product, component, vulnerability, supplier, local, asset, mitigation, authorization, and submission evidence;
7. construct traceable claims with parser and derivation metadata;
8. supersede earlier observations within the same evidence class and scope;
9. retain cross-class contradictions until an explicit scoped adjudication record resolves them;
10. calculate `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, and `C_t`;
11. calculate configured deadline posture independently from recommended state;
12. apply the frozen state rule;
13. retain human authorization and milestone satisfaction as separate events;
14. emit the EvidencePack, state log, conflict report, metrics, source manifest, and append-only audit ledger.

## Ghost-Logger pilot trajectory

| Time | Derived evidence purpose | Expected recommendation | Expected authorization |
|---|---|---|---|
| T+2h | Transitive component, KEV/EPSS, VEX `known_not_affected`, no local execution | Document No-Report | null |
| T+10h | Runtime execution and reachability contradict supplier affectedness | Escalate | null |
| T+14h | Controlled reproduction and scoped conflict resolution | Report-Ready | null |
| T+20h | Explicit human authorization and separate early-warning submission evidence | Report-Ready | Report |
| T+72h | Verified mitigation and full-notification submission evidence | Report-Ready | Report |

The refinement from the proposal's `Report` recommendation to `Report-Ready` plus `authorized_state=Report` is intentional and follows the approved tri-part semantics.

## Realism and interpretation

Ghost-Logger remains fictional. Its Stage 2 value is technical verification: the same result must be derived from representative formats rather than injected YAML conclusions. It does not establish industrial effectiveness or legal correctness.

## Remaining evaluation scenarios

- **False Comfort:** valid but stale or wrongly scoped supplier assurance;
- **Operational Outlier:** high operational impact despite non-extreme technical severity;
- **Rapid Pivot:** unresolved uncertainty and the 18-hour internal safeguard.

Each later scenario must use the same ingestion engine and include at least one negative control.

## Stage 3 scope-aware replay requirements

A supplier assurance may be applied only when its declared scope contains the active target scope. The current canonical dimensions are product PURL, component PURL, CVE, product variant, deployment ID, and environment. Disjoint scopes do not create conflicts.

False Comfort is paired with a negative control:

- the primary replay uses a supplier `known_not_affected` assertion scoped to `standard-profile` and an active `legacy-plugin-profile` deployment;
- the control uses a matching `standard-profile` deployment and no positive local applicability evidence.

Both replays must use the same ingestion, scope, scoring, state, authorization, deadline, and output code. Scenario-specific identifiers are prohibited in application source.

## Stage 4 Operational Outlier requirements

Operational Outlier is paired with a counterfactual lower-impact control. The pair must reuse the exact same non-asset source files, target deployment identity, source timestamps, and deadline profile. The only changed evidence values are asset criticality and deployment scope, which produce different `I_t` values under the frozen impact equation.

The main scenario uses `critical` plus `widespread` context and must reach `Report-Ready` once applicability is confirmed. The control uses `medium` plus `limited` context and must remain `Monitor` under otherwise matched evidence.

CVSS is contextual evidence only and must not be silently added to the state equation. CSAF `under_investigation` must be retained as an assessment-status claim and must not be converted into `product_affectedness=false`.

## Stage 5 Rapid Pivot requirements

Rapid Pivot is paired with an early-resolution temporal control. The pair must use the same source catalog, target, deadline profile, source timestamps, and replay-event timestamps. The only changed treatment is the event at which identity confirmation, EPSS, supplier assessment, and reachability evidence are released.

The primary replay must:

1. derive initial identity confidence from a unique name/version SBOM candidate whose PURL is absent;
2. represent unreleased EPSS, VEX, execution, reachability, and telemetry-reference fields as missing in intermediate scoring snapshots;
3. enter `Prepare` under the frozen uncertainty equation;
4. remain in `Prepare` until a T+18h event;
5. move to `Escalate` through the internal `tau_E` safeguard without an active evidence conflict; and
6. later move to `Report-Ready` after explicit identity confirmation and deployment-specific reachability evidence.

The control must release the exact same resolving artefacts before T+18h and must not trigger the safeguard. Configured deadline posture must remain identical at matched timestamps so the comparison does not conflate the internal state safeguard with workflow-deadline status.

The scenario must not provide `gamma_id`, `U_t`, a precomputed safeguard flag, or any state output. Identity confidence and missingness must be derived from registered source artefacts.

## Stage 5.5 historical replay requirements

The historical replay is external-plausibility evidence and is not a fifth controlled scenario
family. Its public-only mode must distinguish occurrence time from publication and availability
time, reject temporal leakage, preserve source hashes and URLs, and explicitly refuse to generate
organisation-local facts.

The executable reference-deployment manifest may use the common EvidencePack pipeline only when
all organisation-local inputs are visibly classified as synthetic. Public exploitation reporting
may contribute a traceable exploitation claim after publication, but it must not populate the
`local_evidence` block.

Any provisional historical source blocks frozen-evaluation and manuscript eligibility until it is
authoritatively verified or removed from the eligible run.
