"""Schema reconstruction from validation-error oracles (introspection disabled)."""

from __future__ import annotations

from conftest import ScanFn, fired
from gql_scanner.transport import Transport


def test_reconstructs_fields_without_introspection(scan: ScanFn, hard: object) -> None:
    # Hardened disables introspection AND field suggestions; reconstruction must
    # still recover fields by membership testing (no --schema supplied).
    result = scan(hard, no_schema=True)
    assert fired(result, "GQL-SCHEMA-RECONSTRUCTED")
    # The recovered model feeds the access matrix, so its operations appear there.
    names = {op.name for op in result.matrix.operations}
    assert {"me", "user", "users", "search"} <= names


def test_reconstruct_module_directly() -> None:
    from pytest_httpserver import HTTPServer

    from gql_scanner.schema.reconstruct import reconstruct
    from mock_server import hardened

    with HTTPServer() as server:
        server.expect_request("/graphql").respond_with_handler(hardened.handler())
        url = server.url_for("/graphql")
        with Transport(rps=0.0) as t:
            recon = reconstruct(t, url)
    assert recon.found
    assert "me" in recon.query_fields
    assert recon.query_fields.get("me") == "object"  # returns User -> needs selection
    assert "promoteUser" in recon.mutation_fields
