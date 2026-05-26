"""Resolve a :class:`SchemaModel`: introspection over the wire, or a file.

Resolution order (§5.2): an unauthenticated introspection probe runs first so
anonymous exposure is recorded, but when credentials are defined the schema model
prefers an authenticated role's view (routed through the session, so a stale token
is refreshed). A ``--schema`` file, if supplied, overrides the result. If nothing
yields a live schema, the attack surface is reconstructed from validation-error
oracles only when explicitly enabled (``--reconstruct-schema``); otherwise only
schema-independent checks run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from graphql import GraphQLSchema, build_schema

from ..config import UNAUTH_ROLE, ConfigError, Role
from ..exchange import Exchange
from ..transport import Transport
from .introspection import INTROSPECTION_QUERY, parse_introspection
from .model import SchemaModel
from .reconstruct import ReconstructResult, reconstruct, reconstruct_schema

if TYPE_CHECKING:
    from ..session import SessionManager


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
    transport: Transport,
    url: str,
    role: Role | None,
    *,
    session: SessionManager | None = None,
) -> tuple[Exchange, GraphQLSchema | None]:
    """Send the introspection query (optionally as a role); return (exchange, schema).

    When a ``session`` and an authenticated ``role`` are supplied, the request goes
    through the session so a stale token is refreshed + replayed — the same path the
    rest of the scan uses. Otherwise the role's static credentials are sent directly.
    """
    if role is not None and session is not None:
        exchange = session.graphql(transport, role.name, INTROSPECTION_QUERY)
    else:
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
    *,
    session: SessionManager | None = None,
    reconstruct_enabled: bool = False,
) -> SchemaResolution:
    """Resolve the schema, preferring authenticated credentials when they are defined.

    The unauthenticated probe always runs first so ``introspection_enabled`` reflects
    anonymous exposure (the security-relevant signal) and we capture a reachability
    exchange. The schema *model*, however, prefers an authenticated role's view when
    credentials are supplied: an authed user may see a fuller schema, and the scan
    should use the access it was given. Authenticated introspection is routed through
    the ``session`` (when provided) so a stale token is refreshed + replayed. A
    ``--schema`` file overrides everything; failing that, the surface is reconstructed
    from error oracles only when ``reconstruct_enabled`` (``--reconstruct-schema``),
    else only schema-independent checks run.
    """
    # 1. Unauthenticated probe — feeds the introspection-enabled signal and reachability.
    introspection_exchange, anon_schema = _try_introspection(transport, url, None)
    introspection_enabled = anon_schema is not None

    # 2. Prefer authenticated credentials when defined (refresh-aware via the session).
    live_schema: GraphQLSchema | None = None
    introspection_role: str | None = None
    if roles:
        authed = sorted(
            (r for r in roles if r.name != UNAUTH_ROLE and not r.is_unauth),
            key=lambda r: r.name,
        )
        for role in authed:
            _, schema = _try_introspection(transport, url, role, session=session)
            if schema is not None:
                live_schema = schema
                introspection_role = role.name
                break

    # 3. Fall back to the anonymous schema when no authenticated role unlocked one.
    if live_schema is None and anon_schema is not None:
        live_schema = anon_schema
        introspection_role = UNAUTH_ROLE

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
        if introspection_role and introspection_role != UNAUTH_ROLE:
            also = (
                " (also exposed anonymously)"
                if introspection_enabled
                else " (introspection blocked for unauthenticated)"
            )
            note = f"schema loaded from live introspection as role '{introspection_role}'{also}"
        else:
            note = "schema loaded from live introspection (unauthenticated)"
        return SchemaResolution(
            model=SchemaModel.from_schema(live_schema, source="introspection"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=introspection_enabled,
            note=note,
            introspection_role=introspection_role,
        )

    # Last resort: introspection off and no --schema. Optionally recover the attack
    # surface from validation-error oracles (Clairvoyance-style) — off by default
    # because it costs many extra probes; enable with --reconstruct-schema.
    if reconstruct_enabled:
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
        note = (
            "no schema: introspection disabled, --schema not supplied, and reconstruction "
            "recovered nothing (running schema-independent checks only)"
        )
    else:
        note = (
            "no schema: introspection disabled and no --schema supplied; reconstruction is "
            "off (pass --reconstruct-schema to enable) — running schema-independent checks only"
        )

    return SchemaResolution(
        model=None,
        introspection_exchange=introspection_exchange,
        introspection_enabled=False,
        note=note,
    )
