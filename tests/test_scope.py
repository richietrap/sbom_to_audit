from sbom_to_audit.model.scope import (
    ScopeRelation,
    assertion_applies,
    canonicalize_scope,
    scope_relation,
    scopes_overlap,
)

BASE = {
    "product_purl": "pkg:generic/claims-hub@3.8.0",
    "component_purl": "pkg:npm/formula-renderer@5.1.0",
    "cve_id": "CVE-2026-42002",
}


def test_scope_normalization_omits_empty_values() -> None:
    assert canonicalize_scope({**BASE, "deployment_id": "", "environment": None}) == BASE


def test_broad_scope_contains_deployment_specific_scope() -> None:
    deployment = {**BASE, "product_variant": "legacy-plugin-profile"}
    assert scope_relation(BASE, deployment) is ScopeRelation.LEFT_CONTAINS_RIGHT
    assert scopes_overlap(BASE, deployment) is True
    assert assertion_applies(BASE, deployment) is True


def test_conflicting_product_variants_are_disjoint() -> None:
    standard = {**BASE, "product_variant": "standard-profile"}
    legacy = {**BASE, "product_variant": "legacy-plugin-profile"}
    assert scope_relation(standard, legacy) is ScopeRelation.DISJOINT
    assert scopes_overlap(standard, legacy) is False
    assert assertion_applies(standard, legacy) is False


def test_narrow_assertion_does_not_apply_to_broader_unknown_target() -> None:
    standard = {**BASE, "product_variant": "standard-profile"}
    assert assertion_applies(standard, BASE) is False
