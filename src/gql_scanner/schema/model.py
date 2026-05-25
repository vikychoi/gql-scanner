"""Normalized, schema-source-agnostic model of a GraphQL endpoint.

Both the introspection path and the ``--schema`` (SDL or introspection JSON)
path converge on a :class:`graphql.GraphQLSchema`; this module derives a small,
deterministic model from it: the list of root query/mutation fields plus helpers
to build the *minimal valid selection* (and minimal required arguments) used to
probe each operation cheaply and consistently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from graphql import (
    GraphQLArgument,
    GraphQLEnumType,
    GraphQLField,
    GraphQLInputObjectType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLType,
)

# Cap recursion when synthesizing selections/values so cyclic schemas terminate
# deterministically.
_MAX_SELECTION_DEPTH = 4
_LIST_FIELD_NAMES = {"first", "last", "limit", "count", "take", "pageSize"}


def _unwrap(t: GraphQLType) -> GraphQLType:
    while isinstance(t, (GraphQLNonNull, GraphQLList)):
        t = t.of_type
    return t


def _type_name(t: GraphQLType) -> str:
    named = _unwrap(t)
    return getattr(named, "name", "")


def _scalar_literal(scalar_name: str) -> str:
    # Deterministic benign placeholder literals for required scalar arguments.
    return {
        "Int": "1",
        "Float": "1.0",
        "Boolean": "true",
        "ID": '"1"',
        "String": '"gql_scanner"',
    }.get(scalar_name, '"gql_scanner"')


def _arg_value_literal(arg_type: GraphQLType, depth: int = 0) -> str | None:
    """Build a minimal GraphQL literal for a *required* argument, or None to omit."""
    if isinstance(arg_type, GraphQLNonNull):
        inner = _arg_value_literal(arg_type.of_type, depth)
        return inner if inner is not None else "null"
    if depth > _MAX_SELECTION_DEPTH:
        return "null"
    if isinstance(arg_type, GraphQLList):
        return "[]"
    if isinstance(arg_type, GraphQLScalarType):
        return _scalar_literal(arg_type.name)
    if isinstance(arg_type, GraphQLEnumType):
        values = sorted(arg_type.values)
        return values[0] if values else "null"
    if isinstance(arg_type, GraphQLInputObjectType):
        parts: list[str] = []
        for fname in sorted(arg_type.fields):
            f = arg_type.fields[fname]
            if isinstance(f.type, GraphQLNonNull):
                lit = _arg_value_literal(f.type, depth + 1)
                if lit is not None:
                    parts.append(f"{fname}: {lit}")
        return "{" + ", ".join(parts) + "}"
    return "null"


def _render_args(args: dict[str, GraphQLArgument]) -> str:
    """Render only the required arguments as an inline literal arg list."""
    rendered: list[str] = []
    for name in sorted(args):
        arg = args[name]
        if isinstance(arg.type, GraphQLNonNull):
            lit = _arg_value_literal(arg.type)
            if lit is not None:
                rendered.append(f"{name}: {lit}")
    if not rendered:
        return ""
    return "(" + ", ".join(rendered) + ")"


def _render_amount_args(args: dict[str, GraphQLArgument], amount: int) -> str:
    """Like :func:`_render_args` but force list-size args to ``amount`` (DoS probe)."""
    rendered: list[str] = []
    for name in sorted(args):
        arg = args[name]
        required = isinstance(arg.type, GraphQLNonNull)
        if name in _LIST_FIELD_NAMES and isinstance(_unwrap(arg.type), GraphQLScalarType):
            rendered.append(f"{name}: {amount}")
        elif required:
            lit = _arg_value_literal(arg.type)
            if lit is not None:
                rendered.append(f"{name}: {lit}")
    if not rendered:
        return ""
    return "(" + ", ".join(rendered) + ")"


def _build_selection(t: GraphQLType, schema: GraphQLSchema, depth: int = 0) -> str:
    """Return a minimal sub-selection string (with surrounding braces) or ""."""
    t = _unwrap(t)
    if isinstance(t, (GraphQLScalarType, GraphQLEnumType)):
        return ""  # leaf: no sub-selection needed
    if not isinstance(t, GraphQLObjectType) or depth > _MAX_SELECTION_DEPTH:
        # Interfaces/unions/over-deep: fall back to __typename, always valid.
        return " { __typename }"
    # Prefer the alphabetically-first scalar/enum leaf for determinism & cheapness.
    for fname in sorted(t.fields):
        ftype = _unwrap(t.fields[fname].type)
        if isinstance(ftype, (GraphQLScalarType, GraphQLEnumType)):
            return f" {{ {fname} }}"
    # No scalar leaf: recurse into the first object field.
    for fname in sorted(t.fields):
        sub = _build_selection(t.fields[fname].type, schema, depth + 1)
        if sub:
            return f" {{ {fname}{sub} }}"
    return " { __typename }"


@dataclass(frozen=True)
class Operation:
    """A normalized root query/mutation field."""

    name: str
    operation_type: str  # "query" | "mutation"
    return_type_name: str
    _field: GraphQLField
    _schema: GraphQLSchema
    has_required_args: bool = False
    arg_names: tuple[str, ...] = ()

    @property
    def is_mutation(self) -> bool:
        return self.operation_type == "mutation"

    def document(self, *, amount: int | None = None) -> str:
        """A complete, minimal, valid GraphQL document for this operation.

        When ``amount`` is given, list-size arguments are forced to that value
        (used by the amount/DoS probe). The selection is the smallest valid one.
        """
        if amount is None:
            args = _render_args(self._field.args)
        else:
            args = _render_amount_args(self._field.args, amount)
        selection = _build_selection(self._field.type, self._schema)
        return f"{self.operation_type} {{ {self.name}{args}{selection} }}"

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.operation_type, self.name)

    def id_argument(self) -> str | None:
        """Name of an ID-typed argument (object-by-ID fetch), if any."""
        for name in sorted(self._field.args):
            arg = self._field.args[name]
            unwrapped = _unwrap(arg.type)
            if isinstance(unwrapped, GraphQLScalarType) and unwrapped.name == "ID":
                return name
            if name.lower() in ("id", "ids"):
                return name
        return None

    def document_with_id(self, id_value: str) -> str:
        """Document for an object-by-ID fetch using a chosen ID literal."""
        id_arg = self.id_argument()
        if id_arg is None:
            return self.document()
        rendered: list[str] = [f'{id_arg}: "{id_value}"']
        for name in sorted(self._field.args):
            arg = self._field.args[name]
            if name == id_arg:
                continue
            if isinstance(arg.type, GraphQLNonNull):
                lit = _arg_value_literal(arg.type)
                if lit is not None:
                    rendered.append(f"{name}: {lit}")
        selection = _build_selection(self._field.type, self._schema)
        return f"{self.operation_type} {{ {self.name}({', '.join(rendered)}){selection} }}"

    def nested_document(self, field_name: str, depth: int, leaf: str) -> str:
        """Build a benign depth-``depth`` query nesting a self-referential field."""
        inner = leaf
        for _ in range(max(1, depth)):
            inner = f"{field_name} {{ {inner} }}"
        args = _render_args(self._field.args)
        return f"{self.operation_type} {{ {self.name}{args} {{ {inner} }} }}"

    def string_argument(self) -> str | None:
        """Name of a String-typed argument suitable for injection probing.

        URL/host-like arguments are skipped here (they are SSRF targets, see
        :meth:`url_like_argument`), so generic injection probes land on a plain
        text argument such as a search term.
        """
        url_arg = self.url_like_argument()
        for name in sorted(self._field.args):
            if name == url_arg:
                continue
            stype = _unwrap(self._field.args[name].type)
            if isinstance(stype, GraphQLScalarType) and stype.name == "String":
                return name
        return None

    def url_like_argument(self) -> str | None:
        """Name of a String argument that looks like it takes a URL/host (SSRF)."""
        url_keys = ("url", "uri", "host", "callback", "webhook", "src")
        for name in sorted(self._field.args):
            stype = _unwrap(self._field.args[name].type)
            looks_url = any(k in name.lower() for k in url_keys)
            if looks_url and isinstance(stype, GraphQLScalarType):
                return name
        return None

    def document_with_arg(self, arg_name: str, raw_literal: str) -> str:
        """Render a document forcing ``arg_name`` to ``raw_literal`` (already a literal)."""
        rendered: list[str] = [f"{arg_name}: {raw_literal}"]
        for name in sorted(self._field.args):
            if name == arg_name:
                continue
            arg = self._field.args[name]
            if isinstance(arg.type, GraphQLNonNull):
                lit = _arg_value_literal(arg.type)
                if lit is not None:
                    rendered.append(f"{name}: {lit}")
        selection = _build_selection(self._field.type, self._schema)
        return f"{self.operation_type} {{ {self.name}({', '.join(rendered)}){selection} }}"

    def returns_connection(self) -> bool:
        """True if the return type looks like a Relay connection (edges+pageInfo)."""
        t = _unwrap(self._field.type)
        if isinstance(t, GraphQLObjectType):
            return "edges" in t.fields and "pageInfo" in t.fields
        return False

    def edges_node_document(self) -> str | None:
        """An ``edges { node { <leaf> } }`` document if this returns a connection."""
        t = _unwrap(self._field.type)
        if not isinstance(t, GraphQLObjectType) or "edges" not in t.fields:
            return None
        edge_t = _unwrap(t.fields["edges"].type)
        if not isinstance(edge_t, GraphQLObjectType) or "node" not in edge_t.fields:
            return None
        node_sel = _build_selection(edge_t.fields["node"].type, self._schema) or " { __typename }"
        args = _render_args(self._field.args)
        return f"{self.operation_type} {{ {self.name}{args} {{ edges {{ node{node_sel} }} }} }}"


def _operations(
    root: GraphQLObjectType | None, op_type: str, schema: GraphQLSchema
) -> list[Operation]:
    if root is None:
        return []
    ops: list[Operation] = []
    for name in sorted(root.fields):
        f = root.fields[name]
        required = any(isinstance(a.type, GraphQLNonNull) for a in f.args.values())
        ops.append(
            Operation(
                name=name,
                operation_type=op_type,
                return_type_name=_type_name(f.type),
                _field=f,
                _schema=schema,
                has_required_args=required,
                arg_names=tuple(sorted(f.args)),
            )
        )
    return ops


@dataclass(frozen=True)
class SchemaModel:
    """Deterministic, normalized view of a GraphQL schema."""

    schema: GraphQLSchema
    queries: list[Operation] = field(default_factory=list)
    mutations: list[Operation] = field(default_factory=list)
    source: str = "introspection"  # "introspection" | "schema-file" | "partial"

    @classmethod
    def from_schema(cls, schema: GraphQLSchema, *, source: str) -> SchemaModel:
        return cls(
            schema=schema,
            queries=_operations(schema.query_type, "query", schema),
            mutations=_operations(schema.mutation_type, "mutation", schema),
            source=source,
        )

    @property
    def operations(self) -> list[Operation]:
        """All operations, deterministically ordered."""
        return sorted(self.queries + self.mutations, key=lambda o: o.sort_key)

    def type_names(self) -> list[str]:
        return sorted(n for n in self.schema.type_map if not n.startswith("__"))

    @property
    def has_node_field(self) -> bool:
        names = {o.name for o in self.queries}
        return "node" in names or "nodes" in names

    def find_recursive_path(self) -> tuple[Operation, str, str] | None:
        """Find a query op with a self-referential field for the depth probe.

        Returns ``(operation, recursive_field_name, scalar_leaf_field)`` for the
        first (sorted) query whose return object has a field of its own type.
        """
        for op in self.queries:
            t = _unwrap(op._field.type)
            if not isinstance(t, GraphQLObjectType):
                continue
            for fname in sorted(t.fields):
                ftype = _unwrap(t.fields[fname].type)
                if isinstance(ftype, GraphQLObjectType) and ftype.name == t.name:
                    leaf = _first_scalar_leaf(t)
                    if leaf:
                        return (op, fname, leaf)
        return None

    def list_field_without_pagination(self) -> Operation | None:
        """First query returning a bare list with no pagination-style argument."""
        for op in self.queries:
            if isinstance(_unwrap_to_list(op._field.type), GraphQLList):
                if not (set(op.arg_names) & _LIST_FIELD_NAMES):
                    return op
        return None

    def list_field_with_amount_arg(self) -> Operation | None:
        """First query exposing a list-size argument (first/limit/...)."""
        for op in self.queries:
            if set(op.arg_names) & _LIST_FIELD_NAMES:
                return op
        return None

    def first_string_arg_op(self) -> tuple[Operation, str] | None:
        """First query with a String argument: ``(operation, arg_name)``."""
        for op in self.queries:
            arg = op.string_argument()
            if arg is not None:
                return (op, arg)
        return None

    def first_url_arg_op(self) -> tuple[Operation, str] | None:
        """First query with a URL/host-like String argument."""
        for op in self.queries:
            arg = op.url_like_argument()
            if arg is not None:
                return (op, arg)
        return None


def _first_scalar_leaf(t: GraphQLObjectType) -> str | None:
    for fname in sorted(t.fields):
        if isinstance(_unwrap(t.fields[fname].type), (GraphQLScalarType, GraphQLEnumType)):
            return str(fname)
    return None


def _unwrap_to_list(t: GraphQLType) -> GraphQLType:
    while isinstance(t, GraphQLNonNull):
        t = t.of_type
    return t
