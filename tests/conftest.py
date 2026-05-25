"""Hermetic fixtures: in-process mock GraphQL servers + a scan helper.

No live network (§11). Each scan spins up a real local HTTP server backed by the
requested profile's handler, runs the deterministic engine against it, and tears
the server down.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from gql_scanner.config import Settings, load_roles
from gql_scanner.engine import ScanResult, run_scan
from gql_scanner.transport import Transport
from mock_server import hardened, vulnerable

# Quiet the per-request werkzeug access log during the scan-heavy suite.
logging.getLogger("werkzeug").setLevel(logging.WARNING)

Profile = object  # the profile modules (vulnerable / hardened)

# Roles file: a privileged role (header-authed) plus the implicit unauth role.
ROLES = {"admin": {"headers": {"Authorization": "Bearer test-admin"}}}


@pytest.fixture
def roles_path(tmp_path: Path) -> Path:
    p = tmp_path / "roles.json"
    p.write_text(json.dumps(ROLES), encoding="utf-8")
    return p


def _schema_file(tmp_path: Path, sdl: str) -> Path:
    p = tmp_path / "schema.graphql"
    p.write_text(sdl, encoding="utf-8")
    return p


ScanFn = Callable[..., ScanResult]


@pytest.fixture
def scan(tmp_path: Path, roles_path: Path) -> Iterator[ScanFn]:
    """Return ``scan(profile_module, **settings_overrides) -> ScanResult``.

    One server is started per profile and *reused* across calls within a test, so
    repeated scans hit the same host:port — a precondition for byte-identical
    determinism checks. For the hardened profile (introspection disabled) the
    profile's SDL is passed via ``--schema`` automatically, mirroring real usage.
    """
    servers: dict[str, HTTPServer] = {}

    def _server_for(profile_module: object) -> HTTPServer:
        name = profile_module.PROFILE.name  # type: ignore[attr-defined]
        if name not in servers:
            server = HTTPServer()
            server.start()
            server.expect_request("/graphql").respond_with_handler(
                profile_module.handler()  # type: ignore[attr-defined]
            )
            servers[name] = server
        return servers[name]

    def _run(profile_module: object, **overrides: object) -> ScanResult:
        server = _server_for(profile_module)
        url = server.url_for("/graphql")

        no_schema = bool(overrides.pop("no_schema", False))
        schema_path = overrides.pop("schema_path", None)
        if schema_path is None and not no_schema and not profile_module.PROFILE.introspection:  # type: ignore[attr-defined]
            schema_path = _schema_file(tmp_path, profile_module.SDL)  # type: ignore[attr-defined]

        role_list = overrides.pop("roles", None) or load_roles(roles_path)

        settings = Settings(
            url=url,
            roles=role_list,  # type: ignore[arg-type]
            schema_path=schema_path,  # type: ignore[arg-type]
            findings_out=tmp_path / "findings.csv",
            matrix_out=tmp_path / "matrix.csv",
            rps=0.0,  # no pacing in tests
            **overrides,  # type: ignore[arg-type]
        )
        with Transport(timeout=10.0, rps=0.0) as transport:
            return run_scan(settings, transport)

    yield _run

    for server in servers.values():
        server.stop()


@pytest.fixture
def vuln() -> object:
    return vulnerable


@pytest.fixture
def hard() -> object:
    return hardened


def fired(result: ScanResult, check_id: str) -> bool:
    """True if ``check_id`` produced at least one finding."""
    return any(f.check_id == check_id for f in result.findings)
