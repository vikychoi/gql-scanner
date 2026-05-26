"""Differential injection engine shared by the GQL-INJECTION-* checks.

Instead of grepping one response for an error string, each family sends a benign
*baseline* and one or more *probes*, then scores the divergence:

* SQL — boolean pair (``' OR '1'='1`` vs ``' AND '1'='2``) compared by result
  count, plus an error-based single-quote probe.
* NoSQL — operator-shaped payloads; result divergence or operator/Mongo errors.
* OS command — canary-reflection (``$(echo <nonce>)``, backticks, ``;echo``): if
  the unique nonce or ``uid=`` output appears in the response, the command ran.
  Command-shaped fields are flagged at lower confidence even without reflection.
* SSRF — loopback/metadata URLs into URL-like args; outbound-connection error or
  fetched-content reflection.
* Template/SSTI — ``{{7*7}}`` evaluates to ``49`` while ``{{6*6}}`` → ``36``,
  proving server-side evaluation rather than mere reflection.
* Allowlist — special characters accepted and reflected verbatim (informational).

Every probe is benign (a unique nonce / arithmetic / loopback), bounded, and
deterministic. The engine runs once per scan; the per-class Check objects read
its cached results.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..differential import Fingerprint, Signal, combine_confidence, fingerprint, reflected
from ..exchange import Exchange
from ..findings import Finding, Severity
from ..heuristics import (
    executed_ok,
    looks_like_db_error,
    looks_like_nosql_signal,
    looks_like_os_error,
    looks_like_ssrf_signal,
)
from ..schema.injection_points import InjectionPoint, all_points
from .base import CheckContext

# Deterministic fixed nonce (no randomness in the scan path, §9).
NONCE = "gq7scan9z"
# A benign baseline value deliberately free of NONCE/special chars, so reflection
# guards (e.g. "NONCE not already in baseline") stay correct.
BASELINE_VALUE = "gql_scannerbaseline"
# A finding is emitted only at/above this confidence; the engine still records
# weaker observations for --min-confidence callers below this floor.
_EMIT_FLOOR = 0.35


@dataclass
class _Hit:
    check_id: str
    issue_name: str
    description: str
    severity: Severity
    remediation: str
    evidence: str
    signals: tuple[Signal, ...]
    exchange: Exchange

    def to_finding(self) -> Finding:
        return Finding(
            check_id=self.check_id,
            issue_name=self.issue_name,
            description=self.description,
            severity=self.severity,
            raw_request=self.exchange.raw_request,
            raw_response=self.exchange.raw_response,
            remediation=self.remediation,
            evidence=self.evidence,
            confidence=combine_confidence(self.signals),
            signals="; ".join(str(s) for s in self.signals),
            operation=self.evidence.split(".")[0],  # evidence is "<op>.<arg>..."
        )


class _Prober:
    def __init__(self, ctx: CheckContext) -> None:
        self.ctx = ctx
        # Probe as the primary authenticated role, routed through the session so an
        # expired token is refreshed + replayed mid-scan (the access matrix may have
        # already refreshed it). Without a session, falls back to static creds.
        self.role_name = ctx.primary_role().name

    def send(self, point: InjectionPoint, payload: str) -> Exchange:
        doc, variables = point.build(payload)
        return self.ctx.send(self.role_name, doc, variables=variables)


def _baseline_text(ex: Exchange) -> str:
    return ex.response_body


# --- Per-family detectors. Each returns a list of _Hit (0 or 1). ------------


def _sql(point: InjectionPoint, p: _Prober, base: Exchange, base_fp: Fingerprint) -> list[_Hit]:
    signals: list[Signal] = []
    evidence_ex = base
    # Error-based: a lone single quote.
    err_ex = p.send(point, "gql_scanner'")
    if looks_like_db_error(err_ex):
        signals.append(Signal("sql-error", 0.7, "DB error from single-quote payload"))
        evidence_ex = err_ex
    # Boolean-based: tautology vs contradiction, compared by result count.
    true_ex = p.send(point, "gql_scanner' OR '1'='1")
    false_ex = p.send(point, "gql_scanner' AND '1'='2")
    t_fp, f_fp = fingerprint(true_ex), fingerprint(false_ex)
    if (
        t_fp.result_count >= 0
        and t_fp.result_count > f_fp.result_count
        and t_fp.result_count >= base_fp.result_count
    ):
        signals.append(
            Signal(
                "sql-boolean-divergence",
                0.8,
                f"OR-1=1 returned {t_fp.result_count} rows vs AND-1=2 {f_fp.result_count}",
            )
        )
        evidence_ex = true_ex
    if not signals:
        return []
    return [
        _Hit(
            check_id="GQL-INJECTION-SQL",
            issue_name=f"SQL injection at {point.label}",
            description=(
                f"Input to '{point.label}' alters SQL semantics: a differential probe "
                "changed result count or raised a database error."
            ),
            severity=Severity.HIGH,
            remediation="Use parameterized queries; validate input (Injection).",
            evidence=point.label,
            signals=tuple(signals),
            exchange=evidence_ex,
        )
    ]


def _nosql(point: InjectionPoint, p: _Prober, base: Exchange, base_fp: Fingerprint) -> list[_Hit]:
    signals: list[Signal] = []
    ev = base
    op_ex = p.send(point, '{"$gt": ""}')
    if looks_like_nosql_signal(op_ex):
        signals.append(Signal("nosql-operator-error", 0.6, "operator interpreted/echoed"))
        ev = op_ex
    ne_ex = p.send(point, '{"$ne": null}')
    ne_fp = fingerprint(ne_ex)
    if ne_fp.result_count > base_fp.result_count >= 0:
        signals.append(
            Signal("nosql-operator-divergence", 0.7, f"$ne returned {ne_fp.result_count} rows")
        )
        ev = ne_ex
    if not signals:
        return []
    return [
        _Hit(
            check_id="GQL-INJECTION-NOSQL",
            issue_name=f"NoSQL injection at {point.label}",
            description=(
                f"Operator-shaped input to '{point.label}' was interpreted as a NoSQL "
                "operator (result divergence or operator error)."
            ),
            severity=Severity.HIGH,
            remediation="Reject operator objects; validate input types (Injection).",
            evidence=point.label,
            signals=tuple(signals),
            exchange=ev,
        )
    ]


def _os(point: InjectionPoint, p: _Prober, base: Exchange) -> list[_Hit]:
    base_text = _baseline_text(base)
    signals: list[Signal] = []
    ev = base
    # The inert `$()` separator means the *literal* payload never contains NONCE;
    # only shell execution (which drops `$()`) yields the concatenated NONCE. This
    # distinguishes real command execution from mere input reflection.
    sep = "gq7$()scan9z"  # executes to NONCE ("gq7scan9z")
    payloads = [f";echo {sep}", f"$(echo {sep})", "| id"]
    shell_error = False
    for payload in payloads:
        ex = p.send(point, f"gql_scanner{payload}")
        if reflected(ex, NONCE) and NONCE not in base_text:
            signals.append(Signal("os-cmd-output", 0.9, f"nonce reflected via {payload!r}"))
            ev = ex
            break
        if "uid=" in ex.response_body and "uid=" not in base_text:
            signals.append(Signal("os-cmd-id-output", 0.9, "`id` output present"))
            ev = ex
            break
        if looks_like_os_error(ex) and not looks_like_os_error(base):
            shell_error = True
            ev = ex
    # A shell error (e.g. "/bin/sh: ...") shows input reached a shell, even when
    # no output is echoed back.
    if not signals and shell_error:
        signals.append(Signal("os-shell-error", 0.6, "shell error from command metacharacters"))
    # Command-shaped field without any execution signal: weak structural hint.
    if not signals and point.is_cmd_like:
        signals.append(
            Signal("cmd-shaped-field", 0.2, f"arg '{point.label}' looks command-related")
        )
    if not signals:
        return []
    top = max(s.weight for s in signals)
    sev = Severity.CRITICAL if top >= 0.9 else Severity.HIGH if top >= 0.6 else Severity.LOW
    return [
        _Hit(
            check_id="GQL-INJECTION-OS",
            issue_name=f"OS command injection at {point.label}",
            description=(
                f"Input to '{point.label}' reached an OS command: a unique echo nonce or "
                "`id` output was reflected in the response."
                if top >= 0.9
                else f"Command metacharacters in '{point.label}' produced a shell error."
                if top >= 0.6
                else f"'{point.label}' is shaped like a command argument; verify it is not "
                "passed to a shell."
            ),
            severity=sev,
            remediation="Never pass input to a shell; use exec arrays / allowlists (Injection).",
            evidence=point.label,
            signals=tuple(signals),
            exchange=ev,
        )
    ]


def _ssrf(point: InjectionPoint, p: _Prober, base: Exchange) -> list[_Hit]:
    if not point.is_url_like:
        return []
    signals: list[Signal] = []
    ev = base
    for payload in (f"http://127.0.0.1:9/{NONCE}", "http://169.254.169.254/latest/meta-data/"):
        ex = p.send(point, payload)
        if looks_like_ssrf_signal(ex):
            signals.append(Signal("ssrf-connect-error", 0.7, "outbound connection attempted"))
            ev = ex
            break
    if not signals:
        signals.append(Signal("url-shaped-arg", 0.2, f"'{point.label}' accepts a URL/host"))
    sev = Severity.HIGH if any(s.weight >= 0.6 for s in signals) else Severity.LOW
    return [
        _Hit(
            check_id="GQL-INJECTION-SSRF",
            issue_name=f"SSRF at {point.label}",
            description=(
                f"'{point.label}' takes a URL/host and the server attempted an outbound "
                "fetch to a supplied internal address."
                if sev is Severity.HIGH
                else f"'{point.label}' accepts a URL/host; confirm SSRF protections (allowlist, "
                "block internal ranges)."
            ),
            severity=sev,
            remediation="Allowlist outbound hosts; block internal/metadata ranges (Injection).",
            evidence=point.label,
            signals=tuple(signals),
            exchange=ev,
        )
    ]


def _template(point: InjectionPoint, p: _Prober, base: Exchange) -> list[_Hit]:
    base_text = _baseline_text(base)
    if "49" in base_text or "36" in base_text:
        return []  # ambiguous baseline; skip to avoid a false positive
    ex49 = p.send(point, "{{7*7}}")
    ex36 = p.send(point, "{{6*6}}")
    if reflected(ex49, "49") and reflected(ex36, "36"):
        return [
            _Hit(
                check_id="GQL-INJECTION-TEMPLATE",
                issue_name=f"Template/expression injection at {point.label}",
                description=(
                    f"'{point.label}' evaluates template expressions: {{7*7}}→49 and "
                    "{{6*6}}→36 were computed server-side (SSTI)."
                ),
                severity=Severity.HIGH,
                remediation="Never render user input as a template; sandbox/escape (Injection).",
                evidence=point.label,
                signals=(Signal("template-eval", 0.85, "arithmetic evaluated server-side"),),
                exchange=ex49,
            )
        ]
    return []


def _allowlist(point: InjectionPoint, p: _Prober, base: Exchange) -> list[_Hit]:
    # ID args legitimately echo their value (e.g. node id); only String args make
    # verbatim reflection of special characters a meaningful (encoding) signal.
    if point.scalar_kind != "String":
        return []
    canary = f"gql_scanner<>~{NONCE}"
    ex = p.send(point, canary)
    # Acceptance alone is too noisy (any ID/text arg echoes data back); require the
    # special-character canary to be reflected verbatim — that is the real signal
    # (no output encoding / no input allowlist).
    if not (executed_ok(ex) and reflected(ex, canary)):
        return []
    signals = [Signal("special-chars-reflected", 0.4, "canary reflected verbatim")]
    return [
        _Hit(
            check_id="GQL-INPUT-ALLOWLIST",
            issue_name=f"Unvalidated input at {point.label}",
            description=(
                f"'{point.label}' accepted special characters without validation; "
                "scalar inputs are not constrained to an allowlist."
            ),
            severity=Severity.INFO,
            remediation="Validate scalars against an allowlist (Injection).",
            evidence=point.label,
            signals=tuple(signals),
            exchange=ex,
        )
    ]


def run_injection(ctx: CheckContext) -> dict[str, list[Finding]]:
    """Run every injection family across every injection point, once, memoized."""
    cached = ctx.cache.get("injection")
    if isinstance(cached, dict):
        return cached

    out: dict[str, list[Finding]] = {}
    if ctx.schema is None:
        ctx.cache["injection"] = out
        return out

    prober = _Prober(ctx)
    points = all_points(ctx.schema, include_mutations=ctx.settings.allow_mutations)
    rep = ctx.reporter

    Family = Callable[[InjectionPoint, Exchange, Fingerprint], list[_Hit]]
    families: tuple[tuple[str, Family], ...] = (
        ("SQL injection", lambda pt, b, bfp: _sql(pt, prober, b, bfp)),
        ("NoSQL injection", lambda pt, b, bfp: _nosql(pt, prober, b, bfp)),
        ("OS command injection", lambda pt, b, bfp: _os(pt, prober, b)),
        ("SSRF", lambda pt, b, bfp: _ssrf(pt, prober, b)),
        ("template injection", lambda pt, b, bfp: _template(pt, prober, b)),
        ("input allowlist", lambda pt, b, bfp: _allowlist(pt, prober, b)),
    )

    for point in points:
        base = prober.send(point, BASELINE_VALUE)
        base_fp = fingerprint(base)
        for name, fn in families:
            if rep is not None:
                rep.probe(f"{name} at [cyan]{point.label}[/cyan]")
            for hit in fn(point, base, base_fp):
                finding = hit.to_finding()
                if finding.confidence >= _EMIT_FLOOR:
                    out.setdefault(hit.check_id, []).append(finding)

    ctx.cache["injection"] = out
    return out
