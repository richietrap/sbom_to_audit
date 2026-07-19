"""CSAF 2.0 / VEX parser for vulnerability and product-status assertions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_json

_STATUS_KEYS = (
    "known_affected",
    "known_not_affected",
    "first_affected",
    "last_affected",
    "first_fixed",
    "fixed",
    "under_investigation",
)


def parse_csaf(path: str | Path) -> dict[str, Any]:
    document = read_json(path)
    vulnerabilities = []
    for item in document.get("vulnerabilities", []):
        product_status = item.get("product_status") or {}
        statuses = {
            key: list(product_status.get(key) or [])
            for key in _STATUS_KEYS
            if product_status.get(key) is not None
        }
        vulnerabilities.append(
            {
                "cve": item.get("cve"),
                "title": item.get("title"),
                "product_status": statuses,
                "notes": item.get("notes") or [],
                "remediations": item.get("remediations") or [],
            }
        )
    return {
        "document_tracking_id": ((document.get("document") or {}).get("tracking") or {}).get("id"),
        "document_category": (document.get("document") or {}).get("category"),
        "vulnerabilities": vulnerabilities,
    }
