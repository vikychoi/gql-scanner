from __future__ import annotations

from conftest import ScanFn, fired


def test_excessive_errors_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-EXCESSIVE-ERRORS")


def test_excessive_errors_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-EXCESSIVE-ERRORS")
