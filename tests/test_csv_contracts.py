from __future__ import annotations

import csv
import io

from conftest import ScanFn
from gql_scanner.report.findings_csv import HEADER, render_findings_csv
from gql_scanner.report.matrix_csv import render_matrix_csv


def test_findings_header_exact(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    text = render_findings_csv(result.findings)
    first_line = text.splitlines()[0]
    assert first_line == ",".join(HEADER)
    assert HEADER == [
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


def test_findings_csv_has_no_raw_blobs(scan: ScanFn, vuln: object) -> None:
    # The findings CSV must not carry the full HTTP request/response anymore.
    text = render_findings_csv(scan(vuln).findings)
    assert "HTTP/1.1" not in text and "raw_http" not in text


def test_findings_rows_sorted(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    rows = list(csv.reader(io.StringIO(render_findings_csv(result.findings))))[1:]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    # columns: check_id=0, severity=2, evidence=7
    keys = [(-sev_rank[r[2]], r[0], r[7]) for r in rows]
    assert keys == sorted(keys)


def test_matrix_header_and_unauth_first(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    text = render_matrix_csv(result.matrix)
    header = text.splitlines()[0].split(",")
    assert header[:2] == ["operation_type", "operation_name"]
    assert header[2] == "unauthenticated"
    assert header[3:] == sorted(header[3:])


def test_matrix_rows_sorted(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    rows = list(csv.reader(io.StringIO(render_matrix_csv(result.matrix))))[1:]
    keys = [(r[0], r[1]) for r in rows]
    assert keys == sorted(keys)


def test_matrix_cell_vocabulary(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    rows = list(csv.reader(io.StringIO(render_matrix_csv(result.matrix))))[1:]
    allowed = {"ALLOWED", "DENIED", "ERROR", "SKIPPED", "NOT_TESTED"}
    for row in rows:
        for cell in row[2:]:
            assert cell in allowed
