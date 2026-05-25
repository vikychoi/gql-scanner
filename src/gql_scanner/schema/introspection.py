"""The canonical introspection query and result→schema parsing."""

from __future__ import annotations

from typing import Any, cast

from graphql import GraphQLSchema, build_client_schema, get_introspection_query
from graphql.utilities.get_introspection_query import IntrospectionQuery

# graphql-core's standard introspection query; deterministic and complete.
INTROSPECTION_QUERY: str = get_introspection_query(descriptions=True)


def parse_introspection(data: dict[str, Any]) -> GraphQLSchema:
    """Build a :class:`GraphQLSchema` from an introspection ``data`` payload.

    Accepts either the full ``{"data": {"__schema": ...}}`` document or the inner
    ``{"__schema": ...}`` object.
    """
    if "__schema" not in data and "data" in data:
        data = data["data"]
    if "__schema" not in data:
        raise ValueError("introspection result missing __schema")
    return build_client_schema(cast(IntrospectionQuery, data))
