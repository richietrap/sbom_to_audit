import pytest

from sbom_to_audit.model.identity import apply_identity_uncertainty, identity_confidence


def test_locked_identity_confidence_table():
    assert identity_confidence("exact_versioned_purl") == 1.0
    assert identity_confidence("osv_ecosystem_name_version") == 0.9
    assert identity_confidence("exact_cpe_confirmed") == 0.7
    assert identity_confidence("fuzzy_name_version") == 0.4
    assert identity_confidence("name_only") == 0.2


def test_identity_uncertainty_penalty():
    assert apply_identity_uncertainty(0.1, gamma_id=0.4, lambda_id=0.5) == 0.4


def test_unknown_match_type_is_rejected():
    with pytest.raises(ValueError):
        identity_confidence("invented_match")
