from __future__ import annotations

from conftest import ScanFn, fired
from gql_scanner.heuristics import Access


def _cell(result: object, op_type: str, op_name: str, role: str) -> Access:
    matrix = result.matrix  # type: ignore[attr-defined]
    op = next(o for o in matrix.operations if o.operation_type == op_type and o.name == op_name)
    return matrix.get(op, role).access


def test_unauth_access_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-UNAUTH-ACCESS")


def test_unauth_access_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-UNAUTH-ACCESS")


def test_bola_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-BOLA-IDOR")


def test_bola_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-BOLA-IDOR")


def test_node_field_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-NODE-FIELD-ACCESS")


def test_node_field_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-NODE-FIELD-ACCESS")


def test_edge_node_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-EDGE-NODE-AUTHZ")


def test_edge_node_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-EDGE-NODE-AUTHZ")


def test_bfla_fires_on_vulnerable_with_mutations(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln, allow_mutations=True), "GQL-BFLA")


def test_bfla_not_on_hardened_with_mutations(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard, allow_mutations=True), "GQL-BFLA")


def test_matrix_classification(scan: ScanFn, vuln: object, hard: object) -> None:
    # Vulnerable: anonymous read of `me` resolves data.
    assert _cell(scan(vuln), "query", "me", "unauthenticated") is Access.ALLOWED
    # Hardened: anonymous read of `me` is denied; admin is allowed.
    hardened_result = scan(hard)
    assert _cell(hardened_result, "query", "me", "unauthenticated") is Access.DENIED
    assert _cell(hardened_result, "query", "me", "admin") is Access.ALLOWED


def test_mutations_tested_by_default(scan: ScanFn, vuln: object) -> None:
    # Mutations are probed by default now; vulnerable promoteUser resolves.
    assert _cell(scan(vuln), "mutation", "promoteUser", "admin") is Access.ALLOWED


def test_mutations_skipped_with_skip_flag(scan: ScanFn, vuln: object) -> None:
    assert _cell(scan(vuln, allow_mutations=False), "mutation", "promoteUser", "admin") is (
        Access.SKIPPED
    )
