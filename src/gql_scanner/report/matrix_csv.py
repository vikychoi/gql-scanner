"""Access matrix → CSV (column contract §8.2).

Wide format, one row per operation, one column per role::

    operation_type, operation_name, unauthenticated, <role1>, <role2>, ...

Rows sorted by ``(operation_type, operation_name)``; role columns are
``unauthenticated`` first then alphabetical. UTF-8, ``\\n`` endings.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..accessmatrix import AccessMatrix
from .atomic import write_text_atomic


def render_matrix_csv(matrix: AccessMatrix) -> str:
    roles = matrix.sorted_roles
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["operation_type", "operation_name", *roles])
    for op in matrix.sorted_operations:
        row = [op.operation_type, op.name]
        for role in roles:
            row.append(matrix.get(op, role).access.value)
        writer.writerow(row)
    return buf.getvalue()


def write_matrix_csv(matrix: AccessMatrix, path: Path) -> None:
    write_text_atomic(path, render_matrix_csv(matrix))
