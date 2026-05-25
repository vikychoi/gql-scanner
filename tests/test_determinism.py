from __future__ import annotations

from conftest import ScanFn
from gql_scanner.report.findings_csv import render_findings_csv
from gql_scanner.report.matrix_csv import render_matrix_csv


def test_two_scans_byte_identical(scan: ScanFn, vuln: object) -> None:
    r1 = scan(vuln)
    r2 = scan(vuln)
    assert render_findings_csv(r1.findings) == render_findings_csv(r2.findings)
    assert render_matrix_csv(r1.matrix) == render_matrix_csv(r2.matrix)


def test_hardened_also_deterministic(scan: ScanFn, hard: object) -> None:
    r1 = scan(hard)
    r2 = scan(hard)
    assert render_findings_csv(r1.findings) == render_findings_csv(r2.findings)
    assert render_matrix_csv(r1.matrix) == render_matrix_csv(r2.matrix)
