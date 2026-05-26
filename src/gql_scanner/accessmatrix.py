"""Multi-role + unauthenticated probing → the access matrix (§10).

For every operation × role we send the operation's minimal valid selection with
that role's credentials and classify the result. The resulting matrix is both a
deliverable (matrix CSV) and the substrate for the access-control checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .config import UNAUTH_ROLE, Settings
from .exchange import Exchange
from .heuristics import Access, classify_access
from .schema.model import Operation, SchemaModel
from .session import SessionManager
from .transport import Transport

if TYPE_CHECKING:
    from .report.incremental import IncrementalWriter


@dataclass(frozen=True)
class Cell:
    """One operation×role result: the verdict plus the exchange that produced it."""

    access: Access
    exchange: Exchange | None  # None for SKIPPED / NOT_TESTED


@dataclass
class AccessMatrix:
    """operation → role → Cell, with deterministic ordering helpers."""

    role_names: list[str]
    operations: list[Operation] = field(default_factory=list)
    cells: dict[tuple[str, str], Cell] = field(default_factory=dict)

    def set(self, op: Operation, role: str, cell: Cell) -> None:
        self.cells[(self._op_key(op), role)] = cell

    def get(self, op: Operation, role: str) -> Cell:
        return self.cells.get((self._op_key(op), role), Cell(Access.NOT_TESTED, None))

    @staticmethod
    def _op_key(op: Operation) -> str:
        return f"{op.operation_type}:{op.name}"

    @property
    def sorted_roles(self) -> list[str]:
        """``unauthenticated`` first, then the rest alphabetically (§8.2)."""
        others = sorted(r for r in self.role_names if r != UNAUTH_ROLE)
        head = [UNAUTH_ROLE] if UNAUTH_ROLE in self.role_names else []
        return head + others

    @property
    def sorted_operations(self) -> list[Operation]:
        return sorted(self.operations, key=lambda o: o.sort_key)


def build_access_matrix(
    transport: Transport,
    settings: Settings,
    schema: SchemaModel | None,
    session: SessionManager | None = None,
    *,
    sink: IncrementalWriter | None = None,
) -> AccessMatrix:
    """Probe every operation as every role and classify each result.

    When a :class:`SessionManager` is supplied, requests go through it so that an
    expired credential is refreshed and the probe replayed — otherwise a lapsed
    token would make every cell look ``DENIED`` and the target falsely "hardened".

    When a ``sink`` is supplied it is flushed after each operation's row completes, so
    a scan interrupted mid-matrix still leaves a partial — but valid and correctly
    ordered — matrix CSV on disk.
    """
    role_names = [r.name for r in settings.roles]
    matrix = AccessMatrix(role_names=role_names)
    if schema is None:
        return matrix

    matrix.operations = list(schema.operations)
    session = session or SessionManager(settings.roles, settings.url)
    if sink is not None:
        sink.update_matrix(matrix)  # header + all-NOT_TESTED rows up front

    # Deterministic order: roles sorted, operations sorted.
    for op in matrix.sorted_operations:
        for role_name in sorted(role_names):
            if op.is_mutation and not settings.allow_mutations:
                matrix.set(op, role_name, Cell(Access.SKIPPED, None))
                continue
            exchange = session.request(transport, role_name, op.document())
            matrix.set(op, role_name, Cell(classify_access(exchange), exchange))
        if sink is not None:
            sink.update_matrix(matrix)
    return matrix
