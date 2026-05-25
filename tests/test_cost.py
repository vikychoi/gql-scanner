"""Static cost-model unit tests + directive-overload behavior."""

from __future__ import annotations

from graphql import build_schema

from gql_scanner.checks.base import CheckContext
from gql_scanner.checks.dos_checks import DirectiveOverload
from gql_scanner.config import Settings, default_roles
from gql_scanner.cost import field_cost, has_type_cycle, schema_max_cost
from gql_scanner.exchange import Exchange
from gql_scanner.schema.model import SchemaModel

CYCLIC_SDL = """
type Query { feed: [Post!]! root: Post }
type Post { id: ID! author: User! }
type User { id: ID! posts: [Post!]! }
"""

ACYCLIC_SDL = """
type Query { hello: String me: User }
type User { id: ID! name: String! }
"""


def _model(sdl: str) -> SchemaModel:
    return SchemaModel.from_schema(build_schema(sdl), source="schema-file")


def test_detects_type_cycle() -> None:
    cyclic, path = has_type_cycle(_model(CYCLIC_SDL))
    assert cyclic
    assert "Post" in path and "User" in path


def test_no_cycle_for_acyclic_schema() -> None:
    cyclic, _ = has_type_cycle(_model(ACYCLIC_SDL))
    assert not cyclic


def test_list_field_costs_more_than_scalar() -> None:
    model = _model(CYCLIC_SDL)
    feed = next(o for o in model.queries if o.name == "feed")
    root = next(o for o in model.queries if o.name == "root")
    assert field_cost(feed._field.type) > field_cost(root._field.type)


def test_schema_max_cost_picks_expensive_field() -> None:
    label, cost = schema_max_cost(_model(CYCLIC_SDL))
    assert label == "feed"
    assert cost > 1


class _FakeTransport:
    """Returns a fixed response; simulates a permissive (non-graphql-core) server."""

    def __init__(self, exchange: Exchange) -> None:
        self._ex = exchange

    def graphql(self, *args: object, **kwargs: object) -> Exchange:
        return self._ex


def _ctx(model: SchemaModel, transport: object) -> CheckContext:
    from gql_scanner.accessmatrix import AccessMatrix

    return CheckContext(
        settings=Settings(url="http://x/graphql", roles=default_roles()),
        transport=transport,  # type: ignore[arg-type]
        schema=model,
        matrix=AccessMatrix(role_names=["unauthenticated"]),
        introspection_enabled=True,
    )


def test_directive_overload_fires_when_accepted() -> None:
    ok = Exchange(
        raw_request="POST /graphql",
        raw_response='HTTP/1.1 200 OK\r\n\r\n{"data": {"hello": "hi"}}',
        method="POST",
        url="http://x/graphql",
        status=200,
        elapsed_ms=1,
    )
    findings = DirectiveOverload().run(_ctx(_model(ACYCLIC_SDL), _FakeTransport(ok)))
    assert len(findings) == 1
    assert findings[0].check_id == "GQL-DIRECTIVE-OVERLOAD"


def test_directive_overload_silent_when_rejected() -> None:
    rejected = Exchange(
        raw_request="POST /graphql",
        raw_response='HTTP/1.1 200 OK\r\n\r\n{"errors": [{"message": "duplicate directive"}]}',
        method="POST",
        url="http://x/graphql",
        status=200,
        elapsed_ms=1,
    )
    findings = DirectiveOverload().run(_ctx(_model(ACYCLIC_SDL), _FakeTransport(rejected)))
    assert findings == []
