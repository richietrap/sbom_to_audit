# Paper Claim Matrix

This matrix prevents implementation observations from entering the manuscript without traceable support. `PILOT` entries are provisional and must be regenerated from a tagged Git commit and clean Colab replay before becoming manuscript-eligible.

| Claim ID | Provisional claim | Status | Run or source | Supporting artefact | Required limitation |
|---|---|---|---|---|---|
| PC-001 | The prototype ingests multiple representative security-data formats through one source registry. | PILOT | `GL-STAGE2-PILOT-001` | source manifest; T01; parser tests | Controlled fictional evidence; not industrial validation |
| PC-002 | Source hashes and claim references are generated from committed artefacts rather than supplied by scenario YAML. | PILOT | `GL-STAGE2-PILOT-001` | source manifest; EvidencePack claims; strict-source tests | Hash integrity does not prove substantive source truth |
| PC-003 | The artefact detects the seeded VEX/runtime affectedness conflict. | PILOT | `GL-STAGE2-PILOT-001` | conflict report; `CD=1.0`; T+10 audit event | Seeded conflict; not population-level detection accuracy |
| PC-004 | The artefact preserves conflict resolution rather than deleting contradictory history. | PILOT | `GL-STAGE2-PILOT-001` | audit ledger; T+14 transition | Conflict semantics are scoped but not ontology-complete |
| PC-005 | Human authorization and milestone completion remain separate events. | PILOT | `GL-STAGE2-PILOT-001` | authorization and submission audit events | Prototype behaviour, not legal determination |
| PC-006 | All expected Ghost-Logger states match the frozen pilot oracle. | PILOT | `GL-STAGE2-PILOT-001` | state log; `SC=1.0`; T02 | SC measures rule conformance, not external decision accuracy |
| PC-007 | The six replay outputs are deterministic for identical inputs. | PILOT | release validation | deterministic output hashes | Determinism does not establish real-world correctness |
| PC-008 | Figures and tables are generated from registered machine-readable outputs with preserved hashes. | PILOT | F01, F02, T01, T02 | paper-asset manifest and register | Assets are not manuscript-eligible before tagged rerun |
