from __future__ import annotations

from conftest import ScanFn, fired


def test_suggestions_fire_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-FIELD-SUGGESTIONS")


def test_suggestions_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-FIELD-SUGGESTIONS")
