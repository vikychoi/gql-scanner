from __future__ import annotations

from conftest import ScanFn, fired


def test_introspection_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    assert fired(result, "GQL-INTROSPECTION-ENABLED")


def test_introspection_not_on_hardened(scan: ScanFn, hard: object) -> None:
    result = scan(hard)
    assert not fired(result, "GQL-INTROSPECTION-ENABLED")
