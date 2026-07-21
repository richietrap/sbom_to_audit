# CVE-2024-3400 historical replay

This directory contains a research-normalized historical reconstruction of public evidence
for CVE-2024-3400 / Operation MidnightEclipse.

Two evidence modes are deliberately separated:

1. `public_source_registry.yaml` and `chronology.yaml` reconstruct only evidence that became
   publicly available. This mode does **not** produce an EvidencePack and does not invent
   organisation-local reachability, telemetry, impact, authorization, or legal applicability.
2. `data/scenarios/historical_cve_2024_3400_reference.yaml` combines the public chronology
   with a clearly synthetic reference deployment. It exercises the full EvidencePack pipeline
   but must never be interpreted as a record of any real affected organisation.

The local files under `public_sources/` are concise research-normalized fact extracts, not
copies of the source publications. Their upstream URLs and temporal metadata are retained in
`public_source_registry.yaml`.

The historical EPSS item is marked `provisional_secondary_reconstruction`. It is suitable for
pipeline testing but blocks frozen-evaluation and manuscript eligibility until verified from
an authoritative FIRST historical archive response or daily dataset.
