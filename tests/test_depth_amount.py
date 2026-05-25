from __future__ import annotations

from conftest import ScanFn, fired


def test_depth_limit_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-DEPTH-LIMIT")


def test_depth_limit_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-DEPTH-LIMIT")


def test_amount_limit_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-AMOUNT-LIMIT")


def test_amount_limit_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-AMOUNT-LIMIT")


def test_pagination_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-PAGINATION")


def test_pagination_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-PAGINATION")


def test_query_cost_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-QUERY-COST")


def test_query_cost_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-QUERY-COST")


def test_timeout_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-TIMEOUT")


def test_timeout_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-TIMEOUT")
