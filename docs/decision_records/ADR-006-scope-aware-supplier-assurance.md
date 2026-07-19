# ADR-006: Scope-Aware Supplier Assurance

- **Status:** Accepted
- **Date:** 2026-07-19
- **Software version:** 0.3.0
- **EvidencePack schema:** 0.2 (unchanged)

## Context

Stage 2 compared claim scopes by exact serialized equality. That was sufficient for Ghost-Logger's first vertical slice but could not distinguish a valid supplier assertion for one product variant from evidence about another deployment variant. Treating all product-level VEX assertions as universally applicable would create false comfort; rejecting all narrow assertions would create false positives.

## Decision

Claims use canonical dimensions:

- `product_purl`;
- `component_purl`;
- `cve_id`;
- optional `product_variant`;
- optional `deployment_id`; and
- optional `environment`.

Omitted optional dimensions are broad constraints. Conflicting values on a shared dimension make scopes disjoint. A supplier assertion applies only when every dimension it specifies is present with the same value in the target deployment scope.

CSAF `product_identification_helper.purl` is retained as product identity. A single CSAF `model_numbers` value is interpreted as the product-variant dimension. The asserted VEX status remains in the EvidencePack even when it is outside the active deployment scope; the effective status becomes `not_applicable_scope_mismatch` and the reason is recorded.

Conflict detection compares contradictory active claims pairwise when their scopes overlap. Disjoint product variants do not create a conflict.

## Consequences

- Ghost-Logger's broad supplier assertion still overlaps its deployment-specific local evidence and continues to produce the intentional T+10h conflict.
- False Comfort's `standard-profile` supplier assertion is not applied to a `legacy-plugin-profile` deployment.
- The negative control proves that the same assertion is applied to a matching `standard-profile` deployment.
- No scenario-specific product or scenario identifiers are allowed in application source.

## Limitations

The scope model is deliberately small and deterministic. It does not yet implement semantic ontologies, version intervals, geographic inheritance, serial-number ranges, or temporal assertion expiry. Staleness remains a later generalisation target.
