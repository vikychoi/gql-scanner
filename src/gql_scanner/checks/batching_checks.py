"""Batching-attack checks (OWASP §"Batching Attacks").

A small fixed N=5 of harmless, non-sensitive operations is used; nothing is
brute-forced (§7.4).

* GQL-ARRAY-BATCHING — POST a JSON array of N identical introspection-free probes;
  if the server returns N results, array batching is enabled.
* GQL-ALIAS-BATCHING — POST one query with N aliased copies of a cheap field; all
  aliases resolving means alias-based amplification is possible.
* GQL-BATCH-RATE-LIMIT — batch N repeated object lookups (benign IDs); no
  per-object/request throttling observed ⇒ finding.
"""

from __future__ import annotations

from ..findings import Finding, Severity
from ..heuristics import batch_executed_count
from .base import Check, CheckContext

_BATCH_N = 5
# A schema-independent, side-effect-free probe usable even without a schema.
_TYPENAME_QUERY = "query { __typename }"


def _first_query_doc(ctx: CheckContext) -> str:
    if ctx.schema is not None and ctx.schema.queries:
        return ctx.schema.queries[0].document()
    return _TYPENAME_QUERY


class ArrayBatching(Check):
    id = "GQL-ARRAY-BATCHING"
    title = "Array-based query batching enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        payload = [{"query": _TYPENAME_QUERY} for _ in range(_BATCH_N)]
        ex = ctx.transport.graphql_batch(ctx.url, payload)
        if ex.ok and ex.status == 200 and batch_executed_count(ex) >= _BATCH_N:
            return [
                Finding(
                    check_id=self.id,
                    issue_name="JSON-array query batching enabled",
                    description=(
                        f"The server accepted a JSON array of {_BATCH_N} operations and "
                        "returned a result per entry, enabling request amplification."
                    ),
                    severity=Severity.MEDIUM,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Disable array batching or bound batch size (Batching Attacks).",
                    evidence=f"array batch of {_BATCH_N} executed",
                )
            ]
        return []


class AliasBatching(Check):
    id = "GQL-ALIAS-BATCHING"
    title = "Alias-based batching enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        base = _first_query_doc(ctx)
        body = base[base.index("{") + 1 : base.rindex("}")].strip()
        aliases = " ".join(f"b{i}: {body}" for i in range(_BATCH_N))
        ex = ctx.transport.graphql(ctx.url, f"query {{ {aliases} }}")
        data = ex.graphql_data()
        resolved = isinstance(data, dict) and sum(1 for k in data if k.startswith("b")) >= _BATCH_N
        if ex.ok and ex.status == 200 and resolved:
            return [
                Finding(
                    check_id=self.id,
                    issue_name="Aliased field batching resolves all aliases",
                    description=(
                        f"A single query with {_BATCH_N} aliased fields resolved every "
                        "alias, enabling amplification within one request."
                    ),
                    severity=Severity.MEDIUM,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Limit aliases / apply cost analysis (Batching Attacks).",
                    evidence=f"{_BATCH_N} aliases resolved",
                )
            ]
        return []


class BatchRateLimit(Check):
    id = "GQL-BATCH-RATE-LIMIT"
    title = "No per-object batch rate limiting"
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        op = next((o for o in ctx.schema.queries if o.id_argument() is not None), None)
        if op is None:
            return []
        # Benign repeated lookups of the same object by a fixed ID set.
        payload = [{"query": op.document_with_id(str(i))} for i in range(_BATCH_N)]
        ex = ctx.transport.graphql_batch(ctx.url, payload)
        if ex.ok and ex.status == 200 and batch_executed_count(ex) >= _BATCH_N:
            return [
                Finding(
                    check_id=self.id,
                    issue_name="Batched object lookups not rate-limited",
                    description=(
                        f"A batch of {_BATCH_N} object-by-ID lookups via '{op.name}' all "
                        "executed, with no per-object/request throttling observed."
                    ),
                    severity=Severity.LOW,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Rate-limit per object/request (Batching Attacks).",
                    evidence=f"{op.name} x{_BATCH_N} batched",
                )
            ]
        return []
