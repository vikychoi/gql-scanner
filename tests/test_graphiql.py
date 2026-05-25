from __future__ import annotations

from conftest import ScanFn, fired


def test_graphiql_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-GRAPHIQL-EXPOSED")


def test_graphiql_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-GRAPHIQL-EXPOSED")
