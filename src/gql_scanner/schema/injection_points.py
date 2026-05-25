"""Enumerate every injectable argument across the schema.

Coverage, not first-match: for each operation we yield an :class:`InjectionPoint`
for every String/ID scalar argument *and* for every String/ID leaf reachable
inside input-object arguments (bounded depth). Each point can render a complete,
valid GraphQL document + variables that places an attacker-controlled payload at
exactly that position via a ``$p`` variable, so payloads need no escaping and the
rest of the operation stays minimally valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from graphql import (
    GraphQLEnumType,
    GraphQLInputObjectType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLScalarType,
    GraphQLType,
)

from .model import Operation, SchemaModel, _arg_value_literal, _build_selection, _unwrap

_MAX_INPUT_DEPTH = 3
_URL_KEYS = ("url", "uri", "host", "callback", "webhook", "src", "endpoint", "link", "path")
_CMD_KEYS = ("cmd", "command", "exec", "shell", "run", "ping", "host", "domain", "diagnostic")
_INJECTABLE_SCALARS = ("String", "ID")


def _type_ref(t: GraphQLType) -> str:
    if isinstance(t, GraphQLNonNull):
        return _type_ref(t.of_type) + "!"
    if isinstance(t, GraphQLList):
        return "[" + _type_ref(t.of_type) + "]"
    return getattr(t, "name", "String")


def _scalar_py(name: str) -> Any:
    return {"Int": 1, "Float": 1.0, "Boolean": True, "ID": "1", "String": "gql_scanner"}.get(
        name, "gql_scanner"
    )


def _input_literal_with_hole(
    input_type: GraphQLInputObjectType, leaf_path: tuple[str, ...], depth: int = 0
) -> str:
    """Render an input-object literal with the field at ``leaf_path`` set to ``$p``."""
    parts: list[str] = []
    for fname in sorted(input_type.fields):
        f = input_type.fields[fname]
        required = isinstance(f.type, GraphQLNonNull)
        if leaf_path and fname == leaf_path[0]:
            inner = _unwrap(f.type)
            if len(leaf_path) == 1:
                parts.append(f"{fname}: $p")
            elif isinstance(inner, GraphQLInputObjectType) and depth < _MAX_INPUT_DEPTH:
                nested = _input_literal_with_hole(inner, leaf_path[1:], depth + 1)
                parts.append(f"{fname}: {nested}")
            continue
        if required:
            lit = _arg_value_literal(f.type)
            if lit is not None:
                parts.append(f"{fname}: {lit}")
    return "{" + ", ".join(parts) + "}"


@dataclass(frozen=True)
class InjectionPoint:
    """A single attacker-controllable String/ID position in an operation."""

    op_type: str
    op_name: str
    arg_name: str
    leaf_path: tuple[str, ...]  # () for a scalar arg; field path inside an input object
    scalar_kind: str  # "String" | "ID"
    var_type_ref: str  # GraphQL type of the $p variable (matches the position)
    is_url_like: bool
    is_cmd_like: bool
    _op: Operation

    @property
    def label(self) -> str:
        return ".".join([self.op_name, self.arg_name, *self.leaf_path])

    def build(self, payload: str) -> tuple[str, dict[str, Any]]:
        """Return ``(document, variables)`` placing ``payload`` at this point."""
        field = self._op._field
        rendered: list[str] = []
        for name in sorted(field.args):
            arg = field.args[name]
            if name == self.arg_name:
                if not self.leaf_path:
                    rendered.append(f"{name}: $p")
                else:
                    inner = _unwrap(arg.type)
                    assert isinstance(inner, GraphQLInputObjectType)
                    rendered.append(f"{name}: {_input_literal_with_hole(inner, self.leaf_path)}")
            elif isinstance(arg.type, GraphQLNonNull):
                lit = _arg_value_literal(arg.type)
                if lit is not None:
                    rendered.append(f"{name}: {lit}")
        args = "(" + ", ".join(rendered) + ")" if rendered else ""
        selection = _build_selection(field.type, self._op._schema)
        doc = f"{self.op_type} Probe($p: {self.var_type_ref}) {{ {self.op_name}{args}{selection} }}"
        return doc, {"p": payload}


def _looks_like(name: str, keys: tuple[str, ...]) -> bool:
    low = name.lower()
    return any(k in low for k in keys)


def _walk_input(
    input_type: GraphQLInputObjectType, prefix: tuple[str, ...], depth: int
) -> list[tuple[tuple[str, ...], str, str]]:
    """Yield (leaf_path, scalar_kind, leaf_type_ref) for injectable leaves."""
    out: list[tuple[tuple[str, ...], str, str]] = []
    if depth > _MAX_INPUT_DEPTH:
        return out
    for fname in sorted(input_type.fields):
        f = input_type.fields[fname]
        inner = _unwrap(f.type)
        path = (*prefix, fname)
        if isinstance(inner, GraphQLScalarType) and inner.name in _INJECTABLE_SCALARS:
            out.append((path, inner.name, _type_ref(f.type)))
        elif isinstance(inner, GraphQLInputObjectType):
            out.extend(_walk_input(inner, path, depth + 1))
    return out


def points_for(op: Operation) -> list[InjectionPoint]:
    """All injection points for one operation, deterministically ordered."""
    points: list[InjectionPoint] = []
    field = op._field
    for arg_name in sorted(field.args):
        arg = field.args[arg_name]
        inner = _unwrap(arg.type)
        if (
            isinstance(inner, (GraphQLScalarType, GraphQLEnumType))
            and getattr(inner, "name", "") in _INJECTABLE_SCALARS
        ):
            points.append(
                InjectionPoint(
                    op_type=op.operation_type,
                    op_name=op.name,
                    arg_name=arg_name,
                    leaf_path=(),
                    scalar_kind=inner.name,
                    var_type_ref=_type_ref(arg.type),
                    is_url_like=_looks_like(arg_name, _URL_KEYS),
                    is_cmd_like=_looks_like(arg_name, _CMD_KEYS) or _looks_like(op.name, _CMD_KEYS),
                    _op=op,
                )
            )
        elif isinstance(inner, GraphQLInputObjectType):
            for leaf_path, kind, leaf_ref in _walk_input(inner, (), 0):
                full = (arg_name, *leaf_path)
                points.append(
                    InjectionPoint(
                        op_type=op.operation_type,
                        op_name=op.name,
                        arg_name=arg_name,
                        leaf_path=leaf_path,
                        scalar_kind=kind,
                        var_type_ref=leaf_ref,
                        is_url_like=_looks_like(full[-1], _URL_KEYS),
                        is_cmd_like=_looks_like(full[-1], _CMD_KEYS)
                        or _looks_like(op.name, _CMD_KEYS),
                        _op=op,
                    )
                )
    return points


def all_points(model: SchemaModel, *, include_mutations: bool) -> list[InjectionPoint]:
    ops = list(model.queries)
    if include_mutations:
        ops = ops + list(model.mutations)
    out: list[InjectionPoint] = []
    for op in sorted(ops, key=lambda o: o.sort_key):
        out.extend(points_for(op))
    return out
