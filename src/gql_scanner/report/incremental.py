"""Crash-safe, incremental mirror of the CSV outputs (live updates during a scan).

The engine streams findings and access-matrix progress here as they are produced, so
a scan interrupted (Ctrl-C, timeout, crash) still leaves valid, contract-ordered CSVs
of everything found so far. On clean completion the CLI re-writes the same paths, so
the final artifacts are byte-identical to a non-incremental run. Each update rewrites
the whole file atomically — finding counts are small — which keeps the partial file
sorted and de-duplicated exactly like the final one, never a half-written row.
"""

from __future__ import annotations

from pathlib import Path

from ..accessmatrix import AccessMatrix
from ..findings import Finding, finalize_findings
from .atomic import write_text_atomic
from .findings_csv import render_findings_csv
from .matrix_csv import render_matrix_csv


class IncrementalWriter:
    """Live, atomic writer for the findings and access-matrix CSVs."""

    def __init__(
        self, findings_path: Path, matrix_path: Path, *, min_confidence: float = 0.0
    ) -> None:
        self._findings_path = findings_path
        self._matrix_path = matrix_path
        self._min_confidence = min_confidence
        self._findings: list[Finding] = []

    def begin(self) -> None:
        """Materialize an empty (header-only) findings file so the artifact exists."""
        self._flush_findings()

    def add_findings(self, findings: list[Finding]) -> None:
        """Accumulate a check's findings and re-flush the findings CSV."""
        if not findings:
            return
        self._findings.extend(findings)
        self._flush_findings()

    def update_matrix(self, matrix: AccessMatrix) -> None:
        """Re-flush the access-matrix CSV (rows are already in deterministic order)."""
        write_text_atomic(self._matrix_path, render_matrix_csv(matrix))

    def _flush_findings(self) -> None:
        final = finalize_findings(self._findings, self._min_confidence)
        write_text_atomic(self._findings_path, render_findings_csv(final))
