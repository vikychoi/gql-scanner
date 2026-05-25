"""Load and validate inputs: roles/credentials JSON and the Settings dataclass.

Schema-file loading lives in :mod:`gql_scanner.schema.loader`; this module owns the
roles contract (§5.1) and the immutable run configuration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

UNAUTH_ROLE = "unauthenticated"
_ALLOWED_ROLE_KEYS = {"headers", "cookies", "owns", "privilege"}


class ConfigError(Exception):
    """Raised on invalid user-supplied configuration (maps to exit code 2)."""


@dataclass(frozen=True)
class Role:
    """One authentication identity plus optional authorization ground truth.

    ``owns`` maps an object-by-id query field name (e.g. ``"paste"``) to the IDs
    this role legitimately owns; it lets the BOLA check verify that *another*
    role cannot read those IDs. ``privilege`` (higher = more access) lets the
    BFLA check detect privilege inversion. Both are optional.
    """

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    owns: dict[str, tuple[str, ...]] = field(default_factory=dict)
    privilege: int = 0

    @property
    def is_unauth(self) -> bool:
        return not self.headers and not self.cookies


def _validate_str_map(value: object, *, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a JSON object of string→string")
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ConfigError(f"{where} entries must be string keys and string values")
        out[k] = v
    return out


def _validate_owns(value: object, *, name: str) -> dict[str, tuple[str, ...]]:
    """Validate a role's ``owns``: {object_field: [id, ...]} with string-coerced ids."""
    if not isinstance(value, dict):
        raise ConfigError(f"role {name!r} 'owns' must be an object of field→[ids]")
    out: dict[str, tuple[str, ...]] = {}
    for field_name, ids in value.items():
        if not isinstance(field_name, str):
            raise ConfigError(f"role {name!r} 'owns' keys must be strings")
        if not isinstance(ids, list):
            raise ConfigError(f"role {name!r} 'owns.{field_name}' must be a list of ids")
        coerced: list[str] = []
        for i in ids:
            if isinstance(i, bool) or not isinstance(i, (str, int)):
                raise ConfigError(f"role {name!r} 'owns.{field_name}' ids must be strings/ints")
            coerced.append(str(i))
        out[field_name] = tuple(coerced)
    return out


def _csv_safe(name: str) -> bool:
    # Reject control chars and the CSV-injection lead characters.
    if any(ord(c) < 0x20 for c in name):
        return False
    return name[0] not in "=+-@" if name else False


def default_roles() -> list[Role]:
    """Roles to use when no ``--roles`` file is supplied: unauthenticated only."""
    return [Role(name=UNAUTH_ROLE)]


def load_roles(path: Path) -> list[Role]:
    """Parse and validate the roles JSON, injecting the synthetic unauth role.

    Returns roles sorted by name (deterministic), with ``unauthenticated`` always
    present (honoring a user-declared one if given).
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"roles file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"roles file is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("roles file must be a JSON object mapping role→credentials")

    roles: dict[str, Role] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name.strip():
            raise ConfigError("role names must be non-empty strings")
        if not _csv_safe(name):
            raise ConfigError(f"role name is not CSV-safe: {name!r}")
        if not isinstance(spec, dict):
            raise ConfigError(f"role {name!r} must map to an object")
        unknown = set(spec) - _ALLOWED_ROLE_KEYS
        if unknown:
            raise ConfigError(f"role {name!r} has unknown keys: {sorted(unknown)}")
        headers = _validate_str_map(spec.get("headers", {}), where=f"role {name!r} headers")
        cookies = _validate_str_map(spec.get("cookies", {}), where=f"role {name!r} cookies")
        owns = _validate_owns(spec.get("owns", {}), name=name)
        privilege = spec.get("privilege", 0)
        if not isinstance(privilege, int) or isinstance(privilege, bool):
            raise ConfigError(f"role {name!r} 'privilege' must be an integer")
        roles[name] = Role(
            name=name, headers=headers, cookies=cookies, owns=owns, privilege=privilege
        )

    if UNAUTH_ROLE not in roles:
        roles[UNAUTH_ROLE] = Role(name=UNAUTH_ROLE)

    return [roles[name] for name in sorted(roles)]


@dataclass(frozen=True)
class Settings:
    """Immutable run configuration assembled by the CLI."""

    url: str
    roles: list[Role]
    schema_path: Path | None = None
    findings_out: Path = Path("./gql-scanner-findings.csv")
    matrix_out: Path = Path("./gql-scanner-access-matrix.csv")
    json_out: Path | None = None
    checks: list[str] | None = None
    skip: list[str] = field(default_factory=list)
    allow_mutations: bool = True
    timeout: float = 15.0
    max_depth: int = 15
    rps: float = 5.0
    proxy: str | None = None
    insecure: bool = False
    fail_on: str = "none"
    min_confidence: float = 0.0  # drop findings below this confidence (0 = keep all)
    verbose: bool = False
