"""Resolve a :class:`SchemaModel`: introspection over the wire, or a file.

Resolution order (§5.2): if ``--schema`` is supplied it is preferred and the
override is noted. Otherwise we attempt the live introspection query. If neither
yields a schema, callers fall back to schema-independent checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from graphql import GraphQLSchema, build_schema

from ..config import ConfigError
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
    introspection_enabled: bool
    note: str
    reconstruction: ReconstructResult | None = None


def resolve_schema(transport: Transport, url: str, schema_path: Path | None) -> SchemaResolution:
    """Resolve the schema, recording whether introspection was enabled."""
    introspection_exchange: Exchange | None = None
    introspection_enabled = False

    # Always probe introspection so the introspection check + matrix have signal.
    exchange = transport.graphql(url, INTROSPECTION_QUERY)
    introspection_exchange = exchange
    live_schema: GraphQLSchema | None = None
    if exchange.ok and exchange.status == 200:
        data = exchange.graphql_data()
        if isinstance(data, dict) and "__schema" in data:
            try:
                live_schema = parse_introspection(data)
                introspection_enabled = True
            except (ValueError, TypeError, KeyError):
                live_schema = None

    if schema_path is not None:
        file_schema = load_schema_file(schema_path)
        note = (
            "schema file supplied; introspection also enabled — using file (override)"
            if introspection_enabled
            else "schema loaded from --schema file"
        )
        return SchemaResolution(
            model=SchemaModel.from_schema(file_schema, source="schema-file"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=introspection_enabled,
            note=note,
        )

    if live_schema is not None:
        return SchemaResolution(
            model=SchemaModel.from_schema(live_schema, source="introspection"),
            introspection_exchange=introspection_exchange,
            introspection_enabled=True,
            note="schema loaded from live introspection",
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
