from __future__ import annotations

from typing import Any


def scan_to_dict(scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "status": scan.status,
        "score": scan.score,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "findings": [
            {
                "probe_id": f.probe_id,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "standard_refs": f.standard_refs,
            }
            for f in scan.findings
        ],
    }


def scan_to_sarif(scan, target) -> dict[str, Any]:
    severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules = {}
    results = []
    for f in scan.findings:
        rules[f.probe_id] = {
            "id": f.probe_id,
            "name": f.title,
            "shortDescription": {"text": f.description[:200]},
            "help": {"text": f.remediation},
        }
        results.append({
            "ruleId": f.probe_id,
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target.url},
                }
            }],
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
                "standardRefs": f.standard_refs,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AegisAI Security", "version": "0.2.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }
