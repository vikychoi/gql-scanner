"""In-process mock GraphQL HTTP app with per-control toggles.

A single :class:`Profile` drives every weakness: the ``vulnerable`` profile turns
each control OFF, the ``hardened`` profile applies it correctly. Both serve a
*real* GraphQL endpoint (executed with ``graphql-core``) so the scanner exercises
genuine request/response behavior. Used by both mock servers (§11).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from graphql import (
    DocumentNode,
    FieldNode,
    GraphQLError,
    GraphQLResolveInfo,
    GraphQLSchema,
    OperationDefinitionNode,
    SelectionSetNode,
    build_schema,
    graphql_sync,
    parse,
)
from werkzeug import Request, Response

# --- Profiles ----------------------------------------------------------------


@dataclass(frozen=True)
class Profile:
    name: str
    introspection: bool
    graphiql: bool
    verbose_errors: bool
    field_suggestions: bool
    require_auth: bool
    has_node_field: bool
    paginated_lists: bool
    enforce_depth: int | None
    enforce_amount: int | None
    enforce_cost: int | None
    allow_batching: bool
    validate_input: bool
    edge_node_inconsistent: bool
    allow_get: bool = False
    cors_reflects_origin: bool = False


VULNERABLE = Profile(
    name="vulnerable",
    introspection=True,
    graphiql=True,
    verbose_errors=True,
    field_suggestions=True,
    require_auth=False,
    has_node_field=True,
    paginated_lists=False,
    enforce_depth=None,
    enforce_amount=None,
    enforce_cost=None,
    allow_batching=True,
    validate_input=False,
    edge_node_inconsistent=True,
    allow_get=True,
    cors_reflects_origin=True,
)

HARDENED = Profile(
    name="hardened",
    introspection=False,
    graphiql=False,
    verbose_errors=False,
    field_suggestions=False,
    require_auth=True,
    has_node_field=False,
    paginated_lists=True,
    enforce_depth=5,
    enforce_amount=100,
    enforce_cost=3,
    allow_batching=False,
    validate_input=True,
    edge_node_inconsistent=False,
)

# A realistic *partial* target: well-defended (auth, limits, input validation, no
# batching/GET/CORS) but still leaks its schema via introspection + suggestions.
# Used to test precision — the scanner must flag only the two real leaks.
PARTIAL = Profile(
    name="partial",
    introspection=True,
    graphiql=False,
    verbose_errors=False,
    field_suggestions=True,
    require_auth=True,
    has_node_field=False,
    paginated_lists=True,
    enforce_depth=5,
    enforce_amount=100,
    enforce_cost=3,
    allow_batching=False,
    validate_input=True,
    edge_node_inconsistent=False,
)

# Injection-trigger characters (kept distinct from the allowlist canary chars).
_TRIGGER_CHARS = "'\";$|`"
# Special-but-benign characters used by the allowlist probe.
_SPECIAL_CHARS = "<>~"

_USER = {"id": "1", "name": "Alice", "email": "alice@example.com", "secret": "s3cr3t"}
_POST = {"id": "1", "title": "Hello", "body": "World"}
_COMMENT = {"id": "1", "text": "hi"}

_GRAPHIQL_HTML = (
    "<!DOCTYPE html><html><head><title>GraphiQL</title></head>"
    "<body><div id='graphiql'>Loading GraphiQL...</div></body></html>"
)


def build_sdl(profile: Profile) -> str:
    node_field = "  node(id: ID!): User\n" if profile.has_node_field else ""
    page_arg = "(first: Int)" if profile.paginated_lists else ""
    search_args = "(query: String!, first: Int)" if profile.paginated_lists else "(query: String!)"
    return f"""
    type Query {{
      me: User
      user(id: ID!): User
      users(first: Int): [User!]!
      publicPosts{page_arg}: [Post!]!
      allItems{page_arg}: [Post!]!
{node_field}      search{search_args}: [Post!]!
      fetchUrl(url: String!): String
      comment(id: ID!): Comment
      userConnection(first: Int): UserConnection
    }}

    type Mutation {{
      promoteUser(id: ID!): User
    }}

    type User {{ id: ID!  name: String!  email: String!  secret: String! }}
    type Post {{ id: ID!  title: String!  body: String! }}
    type Comment {{ id: ID!  text: String!  replies: [Comment!]! }}
    type UserConnection {{ totalCount: Int!  edges: [UserEdge!]!  pageInfo: PageInfo! }}
    type UserEdge {{ node: User! }}
    type PageInfo {{ hasNextPage: Boolean! }}
    """


# --- Resolver wiring ----------------------------------------------------------


def _authed(info: GraphQLResolveInfo) -> bool:
    return bool(info.context.get("authed"))


# Per-object ownership ground truth keyed by bearer subject (hardened only): the
# token "Bearer alice" owns user id "1", "Bearer bob" owns "2".
_OWNERSHIP = {"alice": {"1"}, "bob": {"2"}}


def _identity(info: GraphQLResolveInfo) -> str:
    return str(info.context.get("identity") or "")


def _make_schema(profile: Profile) -> GraphQLSchema:
    schema = build_schema(build_sdl(profile))

    def guard(info: GraphQLResolveInfo) -> None:
        if profile.require_auth and not _authed(info):
            raise GraphQLError("Not authorized", extensions={"code": "UNAUTHENTICATED"})

    def r_me(root: Any, info: GraphQLResolveInfo) -> Any:
        guard(info)
        return dict(_USER)

    def r_user(root: Any, info: GraphQLResolveInfo, id: str) -> Any:
        guard(info)
        # Hardened enforces per-object ownership; vulnerable returns any id.
        if profile.require_auth:
            owned = _OWNERSHIP.get(_identity(info), set())
            if id not in owned:
                raise GraphQLError("Not authorized", extensions={"code": "FORBIDDEN"})
        return dict(_USER, id=id)

    def r_users(root: Any, info: GraphQLResolveInfo, first: int | None = None) -> Any:
        guard(info)
        return [dict(_USER)]

    def r_posts(root: Any, info: GraphQLResolveInfo, first: int | None = None) -> Any:
        guard(info)
        return [dict(_POST)]

    def r_node(root: Any, info: GraphQLResolveInfo, id: str) -> Any:
        guard(info)
        return dict(_USER, id=id)

    def r_search(root: Any, info: GraphQLResolveInfo, query: str) -> Any:
        guard(info)
        if profile.validate_input:
            if any(c in query for c in _TRIGGER_CHARS + _SPECIAL_CHARS):
                raise GraphQLError("invalid characters in input")
            return [dict(_POST)]
        # Vulnerable: leak an injection signal keyed to the canary.
        if "'" in query:
            raise GraphQLError("You have an error in your SQL syntax near 'gql_scanner'")
        if "$" in query:
            raise GraphQLError("unknown operator: $gt")
        if ";" in query or "|" in query or "`" in query:
            raise GraphQLError("/bin/sh: 1: echo: command not found")
        # Reflects the search term back unsanitised (no output encoding). Echoed
        # in `body` because that is the alphabetically-first scalar leaf a minimal
        # probe selection picks.
        return [dict(_POST, body=f"results for {query}")]

    def r_fetch(root: Any, info: GraphQLResolveInfo, url: str) -> Any:
        guard(info)
        if profile.validate_input:
            raise GraphQLError("url host not allowed")
        if "127.0.0.1" in url or "localhost" in url:
            raise GraphQLError("connect ECONNREFUSED 127.0.0.1:9")
        return "ok"

    def r_comment(root: Any, info: GraphQLResolveInfo, id: str) -> Any:
        guard(info)
        return dict(_COMMENT, id=id)

    def r_replies(root: Any, info: GraphQLResolveInfo) -> Any:
        return []

    def r_conn(root: Any, info: GraphQLResolveInfo, first: int | None = None) -> Any:
        guard(info)
        return {"authed": _authed(info)}

    def r_total(root: Any, info: GraphQLResolveInfo) -> Any:
        return 1

    def r_edges(root: Any, info: GraphQLResolveInfo) -> Any:
        if profile.edge_node_inconsistent and not _authed(info):
            raise GraphQLError("Not authorized", extensions={"code": "UNAUTHENTICATED"})
        return [{"node": dict(_USER)}]

    def r_pageinfo(root: Any, info: GraphQLResolveInfo) -> Any:
        return {"hasNextPage": False}

    def r_promote(root: Any, info: GraphQLResolveInfo, id: str) -> Any:
        guard(info)
        return dict(_USER, id=id)

    q = schema.query_type
    assert q is not None
    q.fields["me"].resolve = r_me
    q.fields["user"].resolve = r_user
    q.fields["users"].resolve = r_users
    q.fields["publicPosts"].resolve = r_posts
    q.fields["allItems"].resolve = r_posts
    q.fields["search"].resolve = r_search
    q.fields["fetchUrl"].resolve = r_fetch
    q.fields["comment"].resolve = r_comment
    q.fields["userConnection"].resolve = r_conn
    if "node" in q.fields:
        q.fields["node"].resolve = r_node

    schema.type_map["Comment"].fields["replies"].resolve = r_replies  # type: ignore[union-attr]
    conn_t = schema.type_map["UserConnection"]
    conn_t.fields["totalCount"].resolve = r_total  # type: ignore[union-attr]
    conn_t.fields["edges"].resolve = r_edges  # type: ignore[union-attr]
    conn_t.fields["pageInfo"].resolve = r_pageinfo  # type: ignore[union-attr]

    m = schema.mutation_type
    assert m is not None
    m.fields["promoteUser"].resolve = r_promote
    return schema


# --- AST guards (depth / amount / cost / introspection) ----------------------

_AMOUNT_ARGS = {"first", "last", "limit", "count", "take", "pageSize"}


def _max_depth(node: SelectionSetNode | None) -> int:
    if node is None:
        return 0
    best = 0
    for sel in node.selections:
        if isinstance(sel, FieldNode):
            best = max(best, 1 + _max_depth(sel.selection_set))
    return best


def _top_level_count(doc: DocumentNode) -> int:
    total = 0
    for defn in doc.definitions:
        if isinstance(defn, OperationDefinitionNode) and defn.selection_set:
            total += len(defn.selection_set.selections)
    return total


def _max_amount(doc: DocumentNode) -> int:
    found = 0
    for node in doc.definitions:
        for field in _walk_fields(node):
            for arg in field.arguments:
                if arg.name.value in _AMOUNT_ARGS and hasattr(arg.value, "value"):
                    try:
                        found = max(found, int(arg.value.value))  # type: ignore[attr-defined]
                    except (TypeError, ValueError):
                        pass
    return found


def _walk_fields(node: Any) -> list[FieldNode]:
    out: list[FieldNode] = []
    sel = getattr(node, "selection_set", None)
    if sel is None:
        return out
    for s in sel.selections:
        if isinstance(s, FieldNode):
            out.append(s)
            out.extend(_walk_fields(s))
    return out


# --- HTTP handling ------------------------------------------------------------


def _error_body(message: str, *, code: str | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"message": message}
    if code:
        err["extensions"] = {"code": code}
    return {"errors": [err]}


def _execute_one(
    profile: Profile, schema: GraphQLSchema, payload: dict[str, Any], identity: str
) -> dict[str, Any]:
    query = payload.get("query", "")
    variables = payload.get("variables")

    try:
        doc = parse(query)
    except GraphQLError as exc:
        if profile.verbose_errors:
            msg = (
                f"{exc.message}\nTraceback (most recent call last):\n"
                '  File "/app/server.py", line 42, in execute\n    raise\n'
            )
            return {"errors": [{"message": msg}]}
        return {"errors": [{"message": "Syntax error"}]}

    # Introspection block (hardened): refuse __schema/__type.
    if not profile.introspection and ("__schema" in query or "__type" in query):
        return _error_body("GraphQL introspection is not allowed")

    if profile.enforce_depth is not None:
        for defn in doc.definitions:
            if isinstance(defn, OperationDefinitionNode):
                if _max_depth(defn.selection_set) > profile.enforce_depth:
                    return _error_body(
                        f"Query exceeds the maximum depth of {profile.enforce_depth}"
                    )

    if profile.enforce_amount is not None and _max_amount(doc) > profile.enforce_amount:
        return _error_body(f"Requested amount exceeds the maximum of {profile.enforce_amount}")

    if profile.enforce_cost is not None and _top_level_count(doc) > profile.enforce_cost:
        return _error_body("Query is too complex (cost limit exceeded)")

    result = graphql_sync(
        schema,
        query,
        variable_values=variables,
        context_value={"authed": bool(identity), "identity": identity},
    )
    body: dict[str, Any] = {}
    if result.data is not None:
        body["data"] = result.data
    if result.errors:
        errors = []
        for e in result.errors:
            message = e.message
            if not profile.field_suggestions and "Did you mean" in message:
                message = message.split(" Did you mean")[0]
            entry: dict[str, Any] = {"message": message}
            if e.extensions:
                entry["extensions"] = dict(e.extensions)
            errors.append(entry)
        body["errors"] = errors
    return body


def make_handler(profile: Profile):  # type: ignore[no-untyped-def]
    schema = _make_schema(profile)

    def _cors_headers(request: Request) -> dict[str, str]:
        origin = request.headers.get("Origin")
        if profile.cors_reflects_origin and origin:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        return {}

    def _json(out: Any, request: Request) -> Response:
        return Response(
            json.dumps(out),
            status=200,
            content_type="application/json",
            headers=_cors_headers(request),
        )

    def handler(request: Request) -> Response:
        auth = request.headers.get("Authorization", "")
        identity = auth.split()[-1] if auth else ""

        if request.method == "GET":
            query = request.args.get("query")
            if profile.allow_get and query:
                return _json(_execute_one(profile, schema, {"query": query}, identity), request)
            if profile.graphiql:
                return Response(_GRAPHIQL_HTML, status=200, content_type="text/html")
            return Response("GET not supported", status=400, content_type="text/plain")

        try:
            payload = json.loads(request.get_data(as_text=True) or "null")
        except json.JSONDecodeError:
            return Response(
                json.dumps(_error_body("invalid JSON")),
                status=400,
                content_type="application/json",
            )

        if isinstance(payload, list):
            if not profile.allow_batching:
                out: Any = _error_body("Query batching is not allowed")
            else:
                out = [_execute_one(profile, schema, p, identity) for p in payload]
        elif isinstance(payload, dict):
            out = _execute_one(profile, schema, payload, identity)
        else:
            out = _error_body("invalid request")

        return _json(out, request)

    return handler
