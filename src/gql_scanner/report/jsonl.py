"""Optional full machine-readable report (JSONL).

The *only* place a timestamp is allowed (§9.4): an optional run-metadata header
line. Findings lines themselves carry no time-varying data, so they remain
diffable. One JSON object per line.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..engine import ScanResult


def render_jsonl(result: ScanResult, *, url: str, include_timestamp: bool = True) -> str:
    lines: list[str] = []
    meta: dict[str, object] = {
        "record": "run",
        "url": url,
        "schema_note": result.schema_note,
        "introspection_enabled": result.introspection_enabled,
        "target_reachable": result.target_reachable,
        "skipped_checks": result.skipped_checks,
        "finding_count": len(result.findings),
    }
    if include_timestamp:
        meta["generated_at"] = datetime.now(UTC).isoformat()
    lines.append(json.dumps(meta, sort_keys=True))

    for f in result.findings:
        lines.append(
            json.dumps(
                {
                    "record": "finding",
                    "check_id": f.check_id,
                    "issue_name": f.issue_name,
                    "severity": f.severity.label,
                    "confidence": f.confidence,
                    "operation": f.operation,
                    "signals": f.signals,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                    "raw_http_request": f.raw_request,
                    "raw_http_response": f.raw_response,
                    "extra": f.extra,
                },
                sort_keys=True,
            )
        )
    return "\n".join(lines) + "\n"


def write_jsonl(result: ScanResult, path: Path, *, url: str) -> None:
    path.write_text(render_jsonl(result, url=url), encoding="utf-8", newline="")
