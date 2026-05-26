"""Incremental, crash-safe CSV output: partial files stay valid and sorted."""

from __future__ import annotations

import csv
import io

from conftest import ScanFn
from gql_scanner.findings import Finding, Severity
from gql_scanner.report.findings_csv import HEADER, render_findings_csv
from gql_scanner.report.incremental import IncrementalWriter
from gql_scanner.report.matrix_csv import render_matrix_csv


def _finding(check_id: str, severity: Severity, evidence: str) -> Finding:
    return Finding(
        check_id=check_id,
        issue_name=check_id.lower(),
        description="d",
        severity=severity,
        raw_request="",
        raw_response="",
        remediation="r",
        evidence=evidence,
    )


def test_incremental_findings_file_is_valid_and_sorted_midscan(tmp_path) -> None:  # type: ignore[no-untyped-def]
    writer = IncrementalWriter(tmp_path / "findings.csv", tmp_path / "matrix.csv")

    writer.begin()  # the artifact exists (header only) before any finding
    rows = list(csv.reader(io.StringIO((tmp_path / "findings.csv").read_text(encoding="utf-8"))))
    assert rows == [HEADER]

    # Stream findings in non-sorted discovery order, as separate checks would.
    writer.add_findings([_finding("GQL-LOW", Severity.LOW, "z")])
    writer.add_findings([_finding("GQL-HIGH", Severity.HIGH, "a")])

    rows = list(csv.reader(io.StringIO((tmp_path / "findings.csv").read_text(encoding="utf-8"))))
    # Even mid-scan the file is the full contract order (severity desc, check_id asc).
    assert rows[0] == HEADER
    assert rows[1][0] == "GQL-HIGH"
    assert rows[2][0] == "GQL-LOW"


def test_incremental_files_match_full_scan_output(scan: ScanFn, vuln: object, tmp_path) -> None:  # type: ignore[no-untyped-def]
    fpath = tmp_path / "live-findings.csv"
    mpath = tmp_path / "live-matrix.csv"
    sink = IncrementalWriter(fpath, mpath)
    result = scan(vuln, sink=sink, allow_mutations=True)
    # The streamed artifacts are byte-identical to the canonical end-of-scan render.
    assert fpath.read_text(encoding="utf-8") == render_findings_csv(result.findings)
    assert mpath.read_text(encoding="utf-8") == render_matrix_csv(result.matrix)
