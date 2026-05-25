"""Static query-cost modeling from the schema (no abusive requests sent).

A standard complexity model: a scalar costs 1; an object costs 1 plus the cost
of its fields; a list field multiplies its children by an assumed page size.
Summing *all* fields to a depth bound gives the worst-case cost of an all-fields
query — a deterministic upper bound we can flag without ever sending a heavy
request. We also detect type cycles (which make unbounded-depth queries
possible) by DFS over object field return types.
"""

from __future__ import annotations

from graphql import (
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLType,
)

from .schema.model import SchemaModel, _unwrap

# Assumed list page size and depth bound for the static estimate. Fixed constants
# keep the metric deterministic (§9).
ASSUMED_PAGE_SIZE = 10
COST_DEPTH = 6
# Worst-case cost at/above which a field is considered expensive enough to flag.
EXPENSIVE_THRESHOLD = 10_000


def _is_list(t: GraphQLType) -> bool:
    inner = t
    while isinstance(inner, GraphQLNonNull):
        inner = inner.of_type
    return isinstance(inner, GraphQLList)


def _complexity(t: GraphQLType, depth: int, page: int) -> int:
    """Worst-case complexity of selecting every field of ``t`` to ``COST_DEPTH``."""
    inner = _unwrap(t)
    if not isinstance(inner, GraphQLObjectType) or depth >= COST_DEPTH:
        return 1
    total = 1
    for fname in sorted(inner.fields):
        ftype = inner.fields[fname].type
        child = _complexity(ftype, depth + 1, page)
        total += (page if _is_list(ftype) else 1) * child
    return total


def field_cost(field_type: GraphQLType, page: int = ASSUMED_PAGE_SIZE) -> int:
    base = _complexity(field_type, 0, page)
    return base * (page if _is_list(field_type) else 1)


def schema_max_cost(model: SchemaModel) -> tuple[str, int]:
    """Return ``(field_label, worst_case_cost)`` for the most expensive root field."""
    worst_label = ""
    worst = 0
    for op in model.queries:
        cost = field_cost(op._field.type)
        if cost > worst:
            worst, worst_label = cost, op.name
    return worst_label, worst


def has_type_cycle(model: SchemaModel) -> tuple[bool, str]:
    """True (+ a sample path) if some object type is reachable from itself."""
    type_map = model.schema.type_map

    def visit(type_name: str, path: tuple[str, ...]) -> tuple[bool, str]:
        t = type_map.get(type_name)
        if not isinstance(t, GraphQLObjectType):
            return False, ""
        for fname in sorted(t.fields):
            child = _unwrap(t.fields[fname].type)
            if not isinstance(child, GraphQLObjectType) or child.name.startswith("__"):
                continue
            if child.name in path:
                return True, " -> ".join([*path, child.name])
            found, sample = visit(child.name, (*path, child.name))
            if found:
                return True, sample
        return False, ""

    for op in model.queries:
        start = _unwrap(op._field.type)
        if isinstance(start, GraphQLObjectType):
            found, sample = visit(start.name, (start.name,))
            if found:
                return True, sample
    return False, ""
