from __future__ import annotations

import pytest

from conftest import ScanFn, fired

BATCH_CHECKS = ["GQL-ARRAY-BATCHING", "GQL-ALIAS-BATCHING", "GQL-BATCH-RATE-LIMIT"]


@pytest.mark.parametrize("check_id", BATCH_CHECKS)
def test_batching_fires_on_vulnerable(scan: ScanFn, vuln: object, check_id: str) -> None:
    assert fired(scan(vuln), check_id)


@pytest.mark.parametrize("check_id", BATCH_CHECKS)
def test_batching_not_on_hardened(scan: ScanFn, hard: object, check_id: str) -> None:
    assert not fired(scan(hard), check_id)
