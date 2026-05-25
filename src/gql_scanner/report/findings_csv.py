"""Findings → CSV (column contract §8.1).

Columns, in exact order::

    check_id, issue_name, severity, confidence, operation, description,
    remediation, evidence, signals

``operation`` is the query/mutation name the finding concerns; the full verbatim
HTTP request/response are kept out of the CSV (they live in the ``--json-out``
JSONL report) so this file stays scannable. ``confidence`` (0–1, noisy-OR of
corroborating signals) and ``signals`` let callers triage by certainty. Rows are
pre-sorted by the engine (severity desc, check_id asc, evidence asc). UTF-8,
``\\n`` line endings, header first, ``QUOTE_MINIMAL``.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..findings import Finding

HEADER = [
    "check_id",
    "issue_name",
    "severity",
    "confidence",
    "operation",
    "description",
    "remediation",
    "evidence",
    "signals",
]


def render_findings_csv(findings: list[Finding]) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(HEADER)
    for f in findings:
        writer.writerow(
            [
                f.check_id,
                f.issue_name,
                f.severity.label,
                f"{f.confidence:.2f}",
                f.operation,
                f.description,
                f.remediation,
                f.evidence,
                f.signals,
            ]
        )
    return buf.getvalue()


def write_findings_csv(findings: list[Finding], path: Path) -> None:
    path.write_text(render_findings_csv(findings), encoding="utf-8", newline="")
