"""Secure-configuration checks (OWASP GraphQL Cheat Sheet §"Configurations").

Each probe is read-only and schema-independent.

* GQL-INTROSPECTION-ENABLED — sends the standard introspection query; if
  ``__schema`` comes back, introspection is enabled (worse if unauthenticated).
* GQL-GRAPHIQL-EXPOSED — GETs the endpoint and common IDE paths; an HTML IDE
  (GraphiQL/Playground/Sandbox) served in production is a finding.
* GQL-EXCESSIVE-ERRORS — sends a malformed query; stack traces / internal paths
  in the response leak implementation detail.
* GQL-FIELD-SUGGESTIONS — sends a mistyped field; "Did you mean" suggestions ease
  schema discovery when introspection is off.

All probes are safe: they send a read-only query or a syntactically broken one.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..findings import Finding, Severity
from ..heuristics import field_suggestion, looks_like_graphql_ide, looks_like_stack_trace
from ..schema.introspection import INTROSPECTION_QUERY
from .base import Check, CheckContext

# Common IDE/console paths probed via GET, relative to the endpoint origin.
_IDE_PATHS = ("", "/graphiql", "/playground", "/console", "/graphql/console")
# Fallback near-miss field names when no schema is available to derive one from.
_FALLBACK_MISTYPES = ("usr", "nodes", "mee")


def _near_miss(real: str) -> str:
    """Produce a one-edit typo of a real field name to elicit a suggestion."""
    if len(real) >= 4:
        return real[:-1]  # drop last char, e.g. "user" -> "use"
    return real + "x"


class IntrospectionEnabled(Check):
    id = "GQL-INTROSPECTION-ENABLED"
    title = "GraphQL introspection enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        # Probe unauthenticated explicitly so we can flag the worse case.
        ex = ctx.transport.graphql(ctx.url, INTROSPECTION_QUERY)
        data = ex.graphql_data()
        if not (isinstance(data, dict) and "__schema" in data):
            return []
        sev = Severity.MEDIUM
        return [
            Finding(
                check_id=self.id,
                issue_name="Introspection enabled (reachable unauthenticated)",
                description=(
                    "The endpoint answers the standard introspection query without "
                    "credentials, exposing the full schema to anonymous clients."
                ),
                severity=sev,
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Disable introspection in production (Configurations).",
                evidence="__schema returned to unauthenticated client",
            )
        ]


class GraphiQLExposed(Check):
    id = "GQL-GRAPHIQL-EXPOSED"
    title = "GraphQL IDE/console exposed"

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for path in _IDE_PATHS:
            target = ctx.url if path == "" else urljoin(ctx.url + "/", path.lstrip("/"))
            if target in seen:
                continue
            seen.add(target)
            ex = ctx.transport.send("GET", target, headers={"Accept": "text/html"})
            if ex.ok and ex.status == 200 and looks_like_graphql_ide(ex):
                findings.append(
                    Finding(
                        check_id=self.id,
                        issue_name="GraphQL IDE served in production",
                        description=(
                            "An in-browser GraphQL IDE (GraphiQL/Playground/Sandbox) is "
                            f"served at {target}, aiding schema discovery and abuse."
                        ),
                        severity=Severity.LOW,
                        raw_request=ex.raw_request,
                        raw_response=ex.raw_response,
                        remediation="Disable the GraphQL IDE in production (Configurations).",
                        evidence=target,
                    )
                )
        return findings


class ExcessiveErrors(Check):
    id = "GQL-EXCESSIVE-ERRORS"
    title = "Excessive error detail (stack traces)"

    def run(self, ctx: CheckContext) -> list[Finding]:
        # Syntactically broken document; safe — it cannot execute.
        ex = ctx.transport.graphql(ctx.url, "query { __typo @@@ }")
        if ex.ok and looks_like_stack_trace(ex.response_body):
            return [
                Finding(
                    check_id=self.id,
                    issue_name="Verbose errors leak stack traces / internals",
                    description=(
                        "A malformed query elicited a response containing a stack trace "
                        "or internal path, leaking implementation detail."
                    ),
                    severity=Severity.LOW,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Return generic errors; disable debug mode (Configurations).",
                    evidence="stack-trace markers present in error response",
                )
            ]
        return []


class SchemaReconstructed(Check):
    id = "GQL-SCHEMA-RECONSTRUCTED"
    title = "Schema recoverable despite disabled introspection"

    def run(self, ctx: CheckContext) -> list[Finding]:
        recon = ctx.reconstruction
        if recon is None or not recon.found:
            return []
        n = len(recon.query_fields) + len(recon.mutation_fields)
        return [
            Finding(
                check_id=self.id,
                issue_name="Schema reconstructed from error oracles",
                description=(
                    f"Introspection is disabled, but {n} root fields were recovered from "
                    "validation-error messages ('Cannot query field' / 'Did you mean'): "
                    f"{recon.summary()}. Disabling introspection is not a confidentiality control."
                ),
                severity=Severity.LOW,
                raw_request="(schema reconstruction: many membership probes — see jsonl report)",
                raw_response=recon.summary(),
                remediation="Disable field suggestions; treat the schema as public (Config).",
                evidence=f"reconstructed {n} fields in {recon.probes} probes",
                confidence=0.9,
                signals=f"field-enumeration(0.90): {n} fields recovered",
            )
        ]


class FieldSuggestions(Check):
    id = "GQL-FIELD-SUGGESTIONS"
    title = "Field suggestions enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        # Prefer a one-edit typo of a real field (introspection-independent fallback otherwise).
        if ctx.schema is not None and ctx.schema.queries:
            probes = [_near_miss(ctx.schema.queries[0].name)]
        else:
            probes = list(_FALLBACK_MISTYPES)
        ex = None
        suggestion = None
        for probe in probes:
            ex = ctx.transport.graphql(ctx.url, f"query {{ {probe} }}")
            suggestion = field_suggestion(ex)
            if suggestion:
                break
        if ex is None:
            return []
        if suggestion:
            return [
                Finding(
                    check_id=self.id,
                    issue_name="'Did you mean' field suggestions enabled",
                    description=(
                        "The server returns field-name suggestions for mistyped fields, "
                        "letting an attacker enumerate the schema even with introspection off."
                    ),
                    severity=Severity.LOW,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Disable field suggestions in production (Configurations).",
                    evidence=suggestion,
                )
            ]
        return []
