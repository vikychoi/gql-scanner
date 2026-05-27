"""Access-control vs vulnerability scan modes, and the fail-open authz classifier."""

from __future__ import annotations

from conftest import ScanFn, fired
from gql_scanner.exchange import Exchange
from gql_scanner.heuristics import Access, classify_access_control


def _ex(body: str, *, status: int = 200, transport_error: str = "") -> Exchange:
    return Exchange(
        raw_request="POST /graphql",
        raw_response=f"HTTP/1.1 {status} OK\r\n\r\n{body}",
        method="POST",
        url="http://x/graphql",
        status=status,
        elapsed_ms=1,
        transport_error=transport_error,
    )


def test_access_control_classifier_treats_non_authz_error_as_allowed() -> None:
    # Validation/execution error (scanner could not know the right input) => ALLOWED.
    assert classify_access_control(_ex('{"errors":[{"message":"Unknown argument x"}]}')) is (
        Access.ALLOWED
    )
    # A 5xx is not a clean authz block => ALLOWED.
    assert classify_access_control(_ex("boom", status=500)) is Access.ALLOWED
    # Resolved data => ALLOWED.
    assert classify_access_control(_ex('{"data":{"me":{"id":"1"}}}')) is Access.ALLOWED
    # A clean authz denial => DENIED (code or status).
    assert classify_access_control(
        _ex('{"errors":[{"message":"forbidden","extensions":{"code":"FORBIDDEN"}}]}')
    ) is Access.DENIED
    assert classify_access_control(_ex("nope", status=401)) is Access.DENIED
    # No response at all => ERROR (cannot infer access from a transport failure).
    assert classify_access_control(_ex("", status=0, transport_error="ConnectError")) is (
        Access.ERROR
    )


def test_access_control_only_skips_vulnerability_checks(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln, access_control=True, vulnerability=False)
    assert fired(result, "GQL-UNAUTH-ACCESS")  # access-control runs
    assert not fired(result, "GQL-INJECTION-SQL")  # vulnerability skipped
    assert "GQL-INJECTION-SQL" in result.skipped_checks
    assert result.matrix.operations != []  # matrix was built


def test_vulnerability_only_skips_access_control_and_matrix(scan: ScanFn, vuln: object) -> None:
    result = scan(vuln, access_control=False, vulnerability=True)
    assert fired(result, "GQL-INJECTION-SQL")  # vulnerability runs (schema still resolved)
    assert not fired(result, "GQL-UNAUTH-ACCESS")  # access-control skipped
    assert "GQL-UNAUTH-ACCESS" in result.skipped_checks
    assert result.matrix.operations == []  # no authorization probing
