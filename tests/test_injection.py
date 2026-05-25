from __future__ import annotations

import pytest

from conftest import ScanFn, fired

INJECTION_CHECKS = [
    "GQL-INJECTION-SQL",
    "GQL-INJECTION-NOSQL",
    "GQL-INJECTION-OS",
    "GQL-INJECTION-SSRF",
    "GQL-INPUT-ALLOWLIST",
]


@pytest.mark.parametrize("check_id", INJECTION_CHECKS)
def test_injection_fires_on_vulnerable(scan: ScanFn, vuln: object, check_id: str) -> None:
    assert fired(scan(vuln), check_id)


@pytest.mark.parametrize("check_id", INJECTION_CHECKS)
def test_injection_not_on_hardened(scan: ScanFn, hard: object, check_id: str) -> None:
    assert not fired(scan(hard), check_id)
