"""Transport- and protocol-level checks beyond the core OWASP query families.

* GQL-CSRF-GET — GraphQL executed over HTTP GET (and/or form-encoded POST) lets a
  cross-site page issue a simple request; combined with cookie auth that is CSRF.
* GQL-CORS — a permissive CORS policy (reflected ``Origin`` or ``*``), especially
  with ``Allow-Credentials: true``, lets malicious origins read responses.
* GQL-AUTH-BATCH — an authentication mutation that can be aliased N times in one
  request has no per-request anti-automation (password/OTP guessing amplifier).
  Capability detection only: dummy credentials, fixed small N, never a real
  brute force.
"""

from __future__ import annotations

from urllib.parse import quote

from ..findings import Finding, Severity
from .base import Check, CheckContext

_EVIL_ORIGIN = "https://gql_scanner-attacker.example"
_AUTH_KEYWORDS = ("login", "signin", "authenticate", "auth", "token", "verify", "otp", "session")
_AUTH_BATCH_N = 5


class CsrfGet(Check):
    id = "GQL-CSRF-GET"
    title = "GraphQL executes over HTTP GET (CSRF)"

    def run(self, ctx: CheckContext) -> list[Finding]:
        query = "{ __typename }"
        if ctx.schema is not None and ctx.schema.queries:
            query = ctx.schema.queries[0].document()
        target = f"{ctx.url}?query={quote(query)}"
        ex = ctx.transport.send("GET", target, headers={"Accept": "application/json"})
        data = ex.graphql_data()
        executed = ex.ok and ex.status == 200 and isinstance(data, dict) and bool(data)
        if not executed:
            return []
        return [
            Finding(
                check_id=self.id,
                issue_name="GraphQL query executes over HTTP GET",
                description=(
                    "The endpoint executes operations supplied via an HTTP GET query "
                    "string. With cookie-based auth this enables CSRF (and cache/log "
                    "leakage of query contents)."
                ),
                severity=Severity.MEDIUM,
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Require POST + JSON content-type and a CSRF token (Configurations).",
                evidence="GET ?query= executed",
                confidence=0.75,
                signals="get-execution(0.75): query resolved via GET",
            )
        ]


class CorsMisconfig(Check):
    id = "GQL-CORS"
    title = "Permissive CORS policy"

    def run(self, ctx: CheckContext) -> list[Finding]:
        ex = ctx.transport.graphql(
            ctx.url, "{ __typename }", headers={"Origin": _EVIL_ORIGIN}
        )
        acao = ex.response_header("access-control-allow-origin")
        if acao is None:
            return []
        acac = (ex.response_header("access-control-allow-credentials") or "").lower()
        reflected = acao == _EVIL_ORIGIN
        wildcard = acao == "*"
        if not (reflected or wildcard):
            return []
        with_creds = acac == "true"
        # Reflected origin + credentials is the dangerous combination.
        if reflected and with_creds:
            sev, conf, detail = Severity.HIGH, 0.85, "origin reflected with credentials"
        elif reflected:
            sev, conf, detail = Severity.MEDIUM, 0.6, "origin reflected"
        else:
            sev, conf, detail = Severity.LOW, 0.4, "wildcard origin"
        return [
            Finding(
                check_id=self.id,
                issue_name="Permissive CORS policy",
                description=(
                    f"Access-Control-Allow-Origin = {acao!r}"
                    + (f", Allow-Credentials = {acac}" if acac else "")
                    + ". A malicious origin may read authenticated GraphQL responses."
                ),
                severity=sev,
                raw_request=ex.raw_request,
                raw_response=ex.raw_response,
                remediation="Allowlist trusted origins; never reflect Origin with credentials.",
                evidence=f"ACAO={acao}",
                confidence=conf,
                signals=f"cors(*{conf:.2f}): {detail}",
            )
        ]


class AuthBatch(Check):
    id = "GQL-AUTH-BATCH"
    title = "Auth mutation aliasable (no anti-automation)"
    requires_schema = True
    is_mutation_probe = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.schema is None:
            return []
        op = next(
            (m for m in ctx.schema.mutations if any(k in m.name.lower() for k in _AUTH_KEYWORDS)),
            None,
        )
        if op is None:
            return []
        inner = op.document()
        body = inner[inner.index("{") + 1 : inner.rindex("}")].strip()
        aliases = " ".join(f"a{i}: {body}" for i in range(_AUTH_BATCH_N))
        doc = f"mutation {{ {aliases} }}"
        ex = ctx.transport.graphql(ctx.url, doc)
        data = ex.graphql_data()
        n_resolved = sum(1 for k in data if k.startswith("a")) if isinstance(data, dict) else 0
        if ex.ok and ex.status == 200 and n_resolved >= _AUTH_BATCH_N:
            return [
                Finding(
                    check_id=self.id,
                    issue_name=f"auth mutation '{op.name}' is aliasable",
                    description=(
                        f"The authentication mutation '{op.name}' executed {_AUTH_BATCH_N} times "
                        "in a single aliased request — no per-request anti-automation, enabling "
                        "credential/OTP guessing amplification."
                    ),
                    severity=Severity.MEDIUM,
                    raw_request=ex.raw_request,
                    raw_response=ex.raw_response,
                    remediation="Rate-limit auth; reject aliased/batched auth ops (Batching).",
                    evidence=f"mutation:{op.name} x{_AUTH_BATCH_N}",
                    confidence=0.7,
                    signals=f"auth-aliasing(0.70): {_AUTH_BATCH_N} logins in one request",
                )
            ]
        return []
