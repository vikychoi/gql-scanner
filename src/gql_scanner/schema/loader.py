"""Resolve a :class:`SchemaModel`: introspection over the wire, or a file.

Resolution order (§5.2): introspection is attempted **unauthenticated first**
(so anonymous exposure is recorded), then with each supplied role's credentials
in deterministic order (introspection is often allowed for authenticated users
while blocked for anonymous). A ``--schema`` file, if supplied, overrides the
result. If nothing yields a live schema, the attack surface is reconstructed
from validation-error oracles; failing that, only schema-independent checks run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from graphql import GraphQLSchema, build_schema

from ..config import UNAUTH_ROLE, ConfigError, Role
from ..exchange import Exchange
from ..transport import Transport
from .introspection import INTROSPECTION_QUERY, parse_introspection
from .model import SchemaModel
from .reconstruct import ReconstructResult, reconstruct, reconstruct_schema


def load_schema_file(path: Path) -> GraphQLSchema:
    """Load a schema from a file, sniffing introspection-JSON vs SDL."""
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"schema file looks like JSON but failed to parse: {exc}") from exc
        if isinstance(data, dict) and ("__schema" in data or "__schema" in data.get("data", {})):
            return parse_introspection(data)
        raise ConfigError("schema JSON does not contain a __schema introspection result")
    try:
        return build_schema(text)
    except Exception as exc:  # graphql-core raises GraphQLSyntaxError / TypeError
        raise ConfigError(f"could not parse schema file as SDL: {exc}") from exc


@dataclass(frozen=True)
class SchemaResolution:
    """Result of schema resolution, including provenance for the run log."""

    model: SchemaModel | None
    introspection_exchange: Exchange | None
    introspection_enabled: bool  # True only if introspection works *unauthenticated*
    note: str
    reconstruction: ReconstructResult | None = None
    introspection_role: str | None = None  # role whose creds unlocked introspection


def _try_introspection(
    transport: Transport, url: str, role: Role | None
) -> tuple[Exchange, GraphQLSchema | None]:
    """Send the introspection query (optionally as a role); return (exchange, schema)."""
    headers = role.headers or None if role else None
    cookies = role.cookies or None if role else None
    exchange = transport.graphql(url, INTROSPECTION_QUERY, headers=headers, cookies=cookies)
    schema: GraphQLSchema | None = None
    if exchange.ok and exchange.status == 200:
        data = exchange.graphql_data()
        if isinstance(data, dict) and "__schema" in data:
            try:
                schema = parse_introspection(data)
            except (ValueError, TypeError, KeyError):
                schema = None
    return exchange, schema


def resolve_schema(
    transport: Transport,
    url: str,
    schema_path: Path | None,
    roles: list[Role] | None = None,
) -> SchemaResolution:
    """Resolve the schema, trying introspection unauthenticated then per-role.

    Unauthenticated introspection is attempted first so ``introspection_enabled``
    reflects anonymous exposure (the security-relevant signal). If that yields no
    schema, each supplied role's credentials are tried in deterministic order —
    introspection is commonly allowed for authenticated users while blocked for
    anonymous, and the scan should use whatever access it was given.
    """
    # 1. Unauthenticated probe — also feeds the introspection-enabled signal/matrix.
    introspection_exchange, live_schema = _try_introspection(transport, url, None)
    introspection_enabled = live_schema is not None
    introspection_role: str | None = "unauthenticated" if introspection_enabled else None

    # 2. If anon introspection is blocked, try each authenticated role's creds.
    if live_schema is None and roles:
        authed = sorted(
            (r for r in roles if r.name != UNAUTH_ROLE and not r.is_unauth),
            key=lambda r: r.name,
        )
        for role in authed:
            _, schema = _try_introspection(transport, url, role)
            if schema is not None:
                live_schema = schema
                introspection_role = role.name
                break

    if schema_path is not None:
        file_schema = load_schema_file(schema_path)
        note = (
            "schema file supplied; introspection also enabled — using file (override)"
            if live_schema is not None
            else "schema loaded from --schema file"
        )
        return SchemaResolution(
            model=SchemaModel.from_schema(file_schema, source="schema-file"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=introspection_enabled,
            note=note,
            introspection_role=introspection_role,
        )

    if live_schema is not None:
        via = introspection_role or "unauthenticated"
        note = (
            "schema loaded from live introspection"
            if via == "unauthenticated"
            else f"schema loaded from live introspection as role '{via}' "
            "(introspection blocked for unauthenticated)"
        )
        return SchemaResolution(
            model=SchemaModel.from_schema(live_schema, source="introspection"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=introspection_enabled,
            note=note,
            introspection_role=introspection_role,
        )

    # Last resort: introspection off and no --schema. Try to recover the attack
    # surface from validation-error oracles (Clairvoyance-style).
    recon = reconstruct(transport, url)
    if recon.found:
        recon_schema = reconstruct_schema(recon)
        assert recon_schema is not None
        return SchemaResolution(
            model=SchemaModel.from_schema(recon_schema, source="reconstructed"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=False,
            note=(
                f"introspection disabled; reconstructed {len(recon.query_fields)} query + "
                f"{len(recon.mutation_fields)} mutation fields from error oracles"
            ),
            reconstruction=recon,
        )

    return SchemaResolution(
        model=None,
        introspection_exchange=introspection_exchange,
        introspection_enabled=False,
        note="no schema: introspection disabled and no --schema supplied "
        "(running schema-independent checks only)",
    )
