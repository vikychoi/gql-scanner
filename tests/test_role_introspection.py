"""Role-aware schema discovery: introspection blocked for anon, allowed when authed."""

from __future__ import annotations

import dataclasses

from pytest_httpserver import HTTPServer

from gql_scanner.config import UNAUTH_ROLE, Role
from gql_scanner.schema.loader import resolve_schema
from gql_scanner.transport import Transport
from mock_server.app import HARDENED, make_handler

# Hardened, but introspection is permitted for authenticated callers only.
AUTHED_INTROSPECTION = dataclasses.replace(
    HARDENED, name="authed-introspection", introspection_authed_only=True
)

# Introspection exposed to everyone (anon *and* authed): used to confirm a defined
# role's credentials are prioritized for the schema model even when anon also works.
ANON_AND_AUTHED = dataclasses.replace(HARDENED, name="anon-and-authed", introspection=True)

ROLES = [
    Role(name="admin", headers={"Authorization": "Bearer admin"}),
    Role(name=UNAUTH_ROLE),
]


def _resolve(roles: list[Role] | None, *, reconstruct: bool = False) -> object:
    with HTTPServer() as server:
        server.expect_request("/graphql").respond_with_handler(make_handler(AUTHED_INTROSPECTION))
        url = server.url_for("/graphql")
        with Transport(rps=0.0) as t:
            return resolve_schema(t, url, None, roles, reconstruct_enabled=reconstruct)


def test_uses_role_credentials_for_introspection() -> None:
    res = _resolve(ROLES)
    # Anonymous introspection is blocked...
    assert res.introspection_enabled is False
    # ...but a role's credentials unlocked the live schema.
    assert res.introspection_role == "admin"
    assert res.model is not None and res.model.source == "introspection"
    assert {o.name for o in res.model.queries} >= {"me", "user", "search"}


def test_without_roles_reconstructs_when_enabled() -> None:
    # No credentials → anon introspection blocked → reconstruction kicks in (opt-in).
    res = _resolve([Role(name=UNAUTH_ROLE)], reconstruct=True)
    assert res.introspection_enabled is False
    assert res.introspection_role is None
    # It still recovers an attack surface from error oracles.
    assert res.reconstruction is not None and res.reconstruction.found


def test_reconstruction_is_disabled_by_default() -> None:
    # Same blocked target, but without --reconstruct-schema: no model, no probing.
    res = _resolve([Role(name=UNAUTH_ROLE)])
    assert res.model is None
    assert res.reconstruction is None


def test_authenticated_introspection_is_prioritized_when_defined() -> None:
    with HTTPServer() as server:
        server.expect_request("/graphql").respond_with_handler(make_handler(ANON_AND_AUTHED))
        url = server.url_for("/graphql")
        with Transport(rps=0.0) as t:
            res = resolve_schema(t, url, None, ROLES)
    # Anonymous introspection is exposed (the security signal stays True)...
    assert res.introspection_enabled is True
    # ...but because a credentialed role is defined, the schema is fetched as that role.
    assert res.introspection_role == "admin"
    assert res.model is not None and res.model.source == "introspection"
