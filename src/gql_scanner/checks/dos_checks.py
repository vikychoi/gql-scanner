"""DoS-prevention checks (OWASP §"Denial of Service").

Probes detect the *absence of limits*; they never try to exhaust the server.
All magnitudes are fixed module-level constants and hard-capped (§7.3, §9):

* GQL-DEPTH-LIMIT — one benign query nested to ``--max-depth`` via a
  self-referential field; acceptance ⇒ no depth limit.
* GQL-AMOUNT-LIMIT — a single list request with ``first/limit = _MAX_AMOUNT``;
  a large page returned uncapped ⇒ no amount limit.
* GQL-PAGINATION — informational: list fields lacking pagination arguments.
* GQL-QUERY-COST — one fixed composite (aliased) query; execution ⇒ no cost cap.
* GQL-TIMEOUT — one heavy-but-benign query; execution ⇒ no server-side cost/timeout
  guard. Timing is intentionally *not* used (nondeterministic, §9.6).
"""

from __future__ import annotations

from ..cost import EXPENSIVE_THRESHOLD, has_type_cycle, schema_max_cost
from ..differential import Signal, combine_confidence
from ..findings import Finding, Severity
from ..heuristics import executed_ok, looks_like_limit_rejection
from .base import Check, CheckContext

# Hard caps — never escalate, never loop.
_MAX_AMOUNT = 1000
_COST_ALIASES = 10
_DIRECTIVE_REPEATS = 10
_DEPTH_HARD_CAP = 30  # absolute ceiling on probe nesting, regardless of --max-depth


class DepthLimit(Check):
    id = "GQL-DEPTH-LIMIT"
    title = "No query depth limit"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        path = ctx.schema.find_recursive_path()
        if path is None:
            return []
        op, field_name, leaf = path
        depth = min(ctx.settings.max_depth, _DEPTH_HARD_CAP)
        ex = ctx.transport.graphql(ctx.url, op.nested_document(field_name, depth, leaf))
        if ex.ok and ex.status == 200 and not looks_like_limit_rejection(ex):
            return [
                Finding(
                    check_id=self.id,
                    issue_name="No query depth limit enforced",
                    description=(
                        f"A query nested to depth {depth} via '{field_name}' was accepted "
                        "without a depth/complexity rejection."
                    ),
                    severity=Severity.MEDIUM,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Enforce a maximum query depth (Denial of Service).",
                    evidence=f"depth={depth} via {op.name}.{field_name}",
                )
            ]
        return []


class AmountLimit(Check):
    id = "GQL-AMOUNT-LIMIT"
    title = "No pagination amount limit"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        op = ctx.schema.list_field_with_amount_arg()
        if op is None:
            return []
        ex = ctx.transport.graphql(ctx.url, op.document(amount=_MAX_AMOUNT))
        if executed_ok(ex):
            return [
                Finding(
                    check_id=self.id,
                    issue_name="Large page size accepted without cap",
                    description=(
                        f"'{op.name}' accepted a list-size argument of {_MAX_AMOUNT} and "
                        "returned data without enforcing a maximum page size."
                    ),
                    severity=Severity.MEDIUM,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Cap pagination amounts server-side (Denial of Service).",
                    evidence=f"{op.name}(amount={_MAX_AMOUNT})",
                )
            ]
        return []


class Pagination(Check):
    id = "GQL-PAGINATION"
    title = "List field lacks pagination"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        op = ctx.schema.list_field_without_pagination()
        if op is None:
            return []
        ex = ctx.transport.graphql(ctx.url, op.document())
        return [
            Finding(
                check_id=self.id,
                issue_name=f"list field '{op.name}' lacks pagination arguments",
                description=(
                    f"'{op.name}' returns a list but exposes no pagination argument "
                    "(first/last/limit), so callers cannot bound result size."
                ),
                severity=Severity.INFO,
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Add pagination to list fields (Denial of Service).",
                evidence=f"query:{op.name}",
            )
        ]


class QueryCost(Check):
    id = "GQL-QUERY-COST"
    title = "No query cost analysis"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None or not ctx.schema.queries:
            return []
        # Static analysis first: the schema's worst-case cost and any type cycle.
        worst_field, worst_cost = schema_max_cost(ctx.schema)
        cyclic, cycle_path = has_type_cycle(ctx.schema)

        # Dynamic corroboration: does the server execute a composite query?
        op = ctx.schema.queries[0]
        inner = op.document()
        body = inner[inner.index("{") + 1 : inner.rindex("}")].strip()
        aliases = " ".join(f"a{i}: {body}" for i in range(_COST_ALIASES))
        doc = f"query {{ {aliases} }}"
        ex = ctx.transport.graphql(ctx.url, doc)
        executed = ex.ok and ex.status == 200 and not looks_like_limit_rejection(ex)
        # The finding is about a *missing runtime control*: if the server rejected
        # the composite, cost analysis is present — don't fire on schema shape alone.
        if not executed:
            return []

        signals: list[Signal] = [
            Signal("composite-executed", 0.4, f"{_COST_ALIASES} aliased fields executed")
        ]
        if cyclic:
            signals.append(Signal("type-cycle", 0.4, f"cycle: {cycle_path}"))
        if worst_cost >= EXPENSIVE_THRESHOLD:
            signals.append(
                Signal("high-static-cost", 0.4, f"worst field '{worst_field}' ~{worst_cost}")
            )
        if not signals:
            return []
        sig_tuple = tuple(signals)
        return [
            Finding(
                check_id=self.id,
                issue_name="No query cost analysis",
                description=(
                    "No evidence of query cost/complexity analysis: "
                    + (
                        f"the schema's worst-case selection costs ~{worst_cost} units"
                        if worst_cost >= EXPENSIVE_THRESHOLD
                        else "a composite query executed"
                    )
                    + (f"; type cycle enables unbounded depth ({cycle_path})" if cyclic else "")
                    + "."
                ),
                severity=(
                    Severity.MEDIUM
                    if (cyclic or worst_cost >= EXPENSIVE_THRESHOLD)
                    else Severity.INFO
                ),
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Add query cost analysis / complexity limits (Denial of Service).",
                evidence=f"worst={worst_field}:{worst_cost} cyclic={cyclic}",
                confidence=combine_confidence(sig_tuple),
                signals="; ".join(str(s) for s in sig_tuple),
            )
        ]


class DirectiveOverload(Check):
    id = "GQL-DIRECTIVE-OVERLOAD"
    title = "Repeated-directive amplification accepted"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None or not ctx.schema.queries:
            return []
        op = ctx.schema.queries[0]
        inner = op.document()
        # Reattach a fixed number of @include(if:true) directives to the root field.
        # The spec forbids repeated directives; servers that accept them can be
        # amplified. One small, benign query — never escalated.
        head, _, rest = inner.partition(op.name)
        directives = " ".join("@include(if: true)" for _ in range(_DIRECTIVE_REPEATS))
        doc = f"{head}{op.name} {directives}{rest}"
        ex = ctx.transport.graphql(ctx.url, doc)
        if ex.ok and ex.status == 200 and not ex.graphql_errors():
            return [
                Finding(
                    check_id=self.id,
                    issue_name="Repeated directives accepted (amplification)",
                    description=(
                        f"The server accepted {_DIRECTIVE_REPEATS} repeated @include "
                        "directives on one field; the GraphQL spec forbids this, and "
                        "permissive parsers can be amplified."
                    ),
                    severity=Severity.LOW,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Reject duplicate directives; add cost analysis (DoS).",
                    evidence=f"@include x{_DIRECTIVE_REPEATS}",
                    confidence=0.6,
                    signals=f"repeated-directives-accepted(0.60): {_DIRECTIVE_REPEATS} accepted",
                )
            ]
        return []


class Timeout(Check):
    id = "GQL-TIMEOUT"
    title = "No server-side query timeout/cost guard"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        path = ctx.schema.find_recursive_path()
        if path is None:
            return []
        op, field_name, leaf = path
        # A heavy-but-benign moderate nesting; capped, no escalation, timing unused.
        ex = ctx.transport.graphql(ctx.url, op.nested_document(field_name, 8, leaf))
        if ex.ok and ex.status == 200 and not looks_like_limit_rejection(ex):
            return [
                Finding(
                    check_id=self.id,
                    issue_name="No cost/timeout guard on heavy query",
                    description=(
                        "A heavy but benign query executed without a server-side "
                        "cost or timeout rejection."
                    ),
                    severity=Severity.INFO,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Enforce server-side query timeouts/costs (Denial of Service).",
                    evidence=f"heavy query via {op.name}.{field_name}",
                )
            ]
        return []
