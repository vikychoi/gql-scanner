"""GET/CSRF, CORS, and auth-batch checks."""

from __future__ import annotations

from conftest import ScanFn, fired


def test_csrf_get_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    assert fired(scan(vuln), "GQL-CSRF-GET")


def test_csrf_get_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-CSRF-GET")


def test_cors_fires_on_vulnerable(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln)
    assert fired(result, "GQL-CORS")
    cors = next(f for f in result.findings if f.check_id == "GQL-CORS")
    # Reflected origin + credentials => high severity, high confidence.
    assert cors.confidence >= 0.8


def test_cors_not_on_hardened(scan: ScanFn, hard: object) -> None:
    assert not fired(scan(hard), "GQL-CORS")
