"""CSAF 2.0 / VEX parser for scoped product-status assertions."""

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
    if not isinstance(document, dict):
        raise ValueError("CSAF document must be an object")
    document_block = document.get("document") or {}
    if not isinstance(document_block, dict):
        raise ValueError("CSAF document block must be an object")
    if document_block.get("category") not in {"csaf_vex", "csaf_security_advisory"}:
        raise ValueError("CSAF document category must be csaf_vex or csaf_security_advisory")

    products: dict[str, dict[str, Any]] = {}
    product_tree = document.get("product_tree") or {}
    for item in product_tree.get("full_product_names") or []:
        if not isinstance(item, dict):
            continue
        product_id = str(item.get("product_id") or "").strip()
        if product_id:
            products[product_id] = item

    vulnerabilities: list[dict[str, Any]] = []
    for item in document.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        product_status = item.get("product_status") or {}
        statuses = {
            key: [str(value) for value in (product_status.get(key) or [])]
            for key in _STATUS_KEYS
            if product_status.get(key) is not None
        }
        vulnerabilities.append(
            {
                "cve": item.get("cve"),
                "title": item.get("title"),
                "product_status": statuses,
                "notes": item.get("notes") or [],
                "flags": item.get("flags") or [],
                "remediations": item.get("remediations") or [],
            }
        )
    tracking = document_block.get("tracking") or {}
    return {
        "document_tracking_id": tracking.get("id"),
        "document_category": document_block.get("category"),
        "csaf_version": document_block.get("csaf_version"),
        "products": products,
        "vulnerabilities": vulnerabilities,
    }


def product_status_for(
    document: dict[str, Any],
    *,
    cve_id: str,
    product_id: str,
) -> str | None:
    """Return the VEX status assigned to a product for a CVE."""

    for vulnerability in document.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict) or vulnerability.get("cve") != cve_id:
            continue
        statuses = vulnerability.get("product_status") or {}
        for status in _STATUS_KEYS:
            if product_id in (statuses.get(status) or []):
                return status
    return None
