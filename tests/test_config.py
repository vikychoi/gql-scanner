from __future__ import annotations

import json
from pathlib import Path

import pytest

from gql_scanner.config import UNAUTH_ROLE, ConfigError, default_roles, load_roles


def _write(tmp_path: Path, data: object) -> Path:
    p = tmp_path / "roles.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_default_roles_is_unauth_only() -> None:
    roles = default_roles()
    assert [r.name for r in roles] == [UNAUTH_ROLE]
    assert roles[0].is_unauth


def test_load_roles_injects_unauth(tmp_path: Path) -> None:
    roles = load_roles(_write(tmp_path, {"admin": {"headers": {"Authorization": "Bearer x"}}}))
    names = [r.name for r in roles]
    assert names == ["admin", UNAUTH_ROLE]  # sorted, unauth present


def test_load_roles_respects_declared_unauth(tmp_path: Path) -> None:
    roles = load_roles(_write(tmp_path, {UNAUTH_ROLE: {}, "admin": {"cookies": {"s": "1"}}}))
    assert sum(1 for r in roles if r.name == UNAUTH_ROLE) == 1


def test_load_roles_rejects_unknown_keys(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_roles(_write(tmp_path, {"admin": {"token": "x"}}))


def test_load_roles_rejects_non_string_values(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_roles(_write(tmp_path, {"admin": {"headers": {"Authorization": 123}}}))


def test_load_roles_rejects_csv_injection_name(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_roles(_write(tmp_path, {"=cmd": {}}))


def test_load_roles_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_roles(tmp_path / "nope.json")
