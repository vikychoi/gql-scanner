"""Ground-truth authorization tests: ownership-based BOLA and privilege inversion."""

from __future__ import annotations

from conftest import ScanFn, fired
from gql_scanner.checks.access_checks import BrokenFunctionLevelAuthz
from gql_scanner.checks.base import CheckContext
from gql_scanner.config import UNAUTH_ROLE, Role
from gql_scanner.heuristics import Access

# alice owns user#1, bob owns user#2 (matches the mock's _OWNERSHIP).
OWNED_ROLES = [
    Role(name="alice", headers={"Authorization": "Bearer alice"}, owns={"user": ("1",)}),
    Role(name="bob", headers={"Authorization": "Bearer bob"}, owns={"user": ("2",)}),
    Role(name=UNAUTH_ROLE),
]


def test_ownership_bola_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    # Vulnerable: any role can read any user id -> cross-role access detected.
    result = scan(vuln, roles=OWNED_ROLES)
    assert fired(result, "GQL-BOLA-IDOR")
    bola = [f for f in result.findings if f.check_id == "GQL-BOLA-IDOR"]
    assert all(f.confidence >= 0.9 for f in bola)  # ground-truth => high confidence


def test_ownership_bola_clean_on_hardened(scan: ScanFn, hard: object) -> None:
    # Hardened enforces per-object ownership -> no cross-role read.
    result = scan(hard, roles=OWNED_ROLES)
    assert not fired(result, "GQL-BOLA-IDOR")


# --- privilege inversion (unit test over a synthetic matrix) ----------------


class _FakeOp:
    def __init__(self, name: str) -> None:
        self.name = name
        self.operation_type = "query"
        self.is_mutation = False

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.operation_type, self.name)


class _FakeCell:
    def __init__(self, access: Access) -> None:
        self.access = access
        self.exchange = _FakeExchange()


class _FakeExchange:
    raw_request = "GET / HTTP/1.1"
    raw_response = "HTTP/1.1 200 OK"


class _FakeMatrix:
    def __init__(self, op: _FakeOp, cells: dict[str, Access]) -> None:
        self._op = op
        self._cells = cells

    @property
    def sorted_operations(self) -> list[_FakeOp]:
        return [self._op]

    def get(self, op: _FakeOp, role: str) -> _FakeCell:
        return _FakeCell(self._cells[role])


def _ctx(matrix: object, roles: list[Role]) -> CheckContext:
    from gql_scanner.config import Settings

    settings = Settings(url="http://x/graphql", roles=roles)
    return CheckContext(
        settings=settings,
        transport=None,  # type: ignore[arg-type]
        schema=None,
        matrix=matrix,  # type: ignore[arg-type]
        introspection_enabled=False,
    )


def test_privilege_inversion_detected() -> None:
    op = _FakeOp("adminPanel")
    roles = [Role(name="low", privilege=1), Role(name="high", privilege=9)]
    # low (priv 1) ALLOWED but high (priv 9) DENIED -> inversion.
    matrix = _FakeMatrix(op, {"low": Access.ALLOWED, "high": Access.DENIED})
    findings = BrokenFunctionLevelAuthz()._privilege_inversion(_ctx(matrix, roles))
    assert len(findings) == 1
    assert "privilege inversion" in findings[0].issue_name


def test_no_inversion_when_monotonic() -> None:
    op = _FakeOp("adminPanel")
    roles = [Role(name="low", privilege=1), Role(name="high", privilege=9)]
    # high allowed, low denied -> normal RBAC, no finding.
    matrix = _FakeMatrix(op, {"low": Access.DENIED, "high": Access.ALLOWED})
    findings = BrokenFunctionLevelAuthz()._privilege_inversion(_ctx(matrix, roles))
    assert findings == []


def test_no_inversion_without_declared_privileges() -> None:
    op = _FakeOp("adminPanel")
    roles = [Role(name="a"), Role(name="b")]  # both privilege 0
    matrix = _FakeMatrix(op, {"a": Access.ALLOWED, "b": Access.DENIED})
    findings = BrokenFunctionLevelAuthz()._privilege_inversion(_ctx(matrix, roles))
    assert findings == []
