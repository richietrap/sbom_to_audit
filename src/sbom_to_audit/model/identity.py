"""Software-identity confidence model for PURL, OSV, CPE, and fuzzy matches."""

from __future__ import annotations

from dataclasses import dataclass

MATCH_CONFIDENCE: dict[str, float] = {
    "exact_versioned_purl": 1.0,
    "osv_ecosystem_name_version": 0.9,
    "exact_cpe_confirmed": 0.7,
    "fuzzy_name_version": 0.4,
    "name_only": 0.2,
}


def clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def identity_confidence(match_type: str) -> float:
    try:
        return MATCH_CONFIDENCE[match_type]
    except KeyError as exc:
        allowed = ", ".join(sorted(MATCH_CONFIDENCE))
        raise ValueError(f"unknown identity match type {match_type!r}; allowed: {allowed}") from exc


def apply_identity_uncertainty(base_uncertainty: float, gamma_id: float, lambda_id: float = 0.5) -> float:
    if not 0 <= gamma_id <= 1:
        raise ValueError("gamma_id must be within [0,1]")
    if lambda_id < 0:
        raise ValueError("lambda_id must be non-negative")
    return round(clamp(base_uncertainty + lambda_id * (1 - gamma_id)), 6)


@dataclass(frozen=True)
class IdentityResolution:
    primary_identifier: str
    matching_method: str
    gamma_id: float

    @classmethod
    def from_match_type(cls, primary_identifier: str, match_type: str) -> "IdentityResolution":
        return cls(primary_identifier, match_type, identity_confidence(match_type))
