"""Typer CLI — parses args, wires the scan, writes outputs, sets the exit code.

Exit codes (§4): 0 = completed, no findings at/above ``--fail-on``; 1 = findings
at threshold; 2 = usage/config error; 3 = target unreachable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from .config import ConfigError, Settings, default_roles, load_roles
from .engine import run_scan
from .findings import Severity
from .report.findings_csv import write_findings_csv
from .report.jsonl import write_jsonl
from .report.matrix_csv import write_matrix_csv
from .reporter import Reporter
from .transport import Transport

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Deterministic black-box GraphQL security scanner.",
)
# Machine output goes to files; console is human-only (stderr keeps stdout clean).
console = Console(stderr=True)


@app.callback()
def _root() -> None:
    """gql-scanner — audit a GraphQL endpoint against the OWASP GraphQL Cheat Sheet."""


def _split_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


@app.command()
def scan(
    url: str = typer.Option(..., help="GraphQL endpoint URL."),
    roles: Path | None = typer.Option(
        None, help="JSON role→credentials map. Omit to scan as unauthenticated only."
    ),
    schema: Path | None = typer.Option(
        None, help="SDL or introspection JSON (when introspection off)."
    ),
    findings_out: Path = typer.Option(
        Path("./gql-scanner-findings.csv"), help="Findings CSV output path."
    ),
    matrix_out: Path = typer.Option(
        Path("./gql-scanner-access-matrix.csv"), help="Access matrix CSV output path."
    ),
    checks: str | None = typer.Option(None, help="Comma list of check IDs to run (default: all)."),
    skip: str | None = typer.Option(None, help="Comma list of check IDs to skip."),
    allow_mutations: bool = typer.Option(
        True,
        "--allow-mutations/--skip-mutations",
        help="Test mutations (default). Use --skip-mutations for a read-only scan.",
    ),
    timeout: float = typer.Option(15.0, help="Per-request timeout (seconds)."),
    max_depth: int = typer.Option(15, help="Depth used by the depth-limit probe."),
    rps: float = typer.Option(5.0, help="Client-side request pacing (requests/sec)."),
    proxy: str | None = typer.Option(
        None, help="Route all traffic through this proxy URL (e.g. http://127.0.0.1:8080)."
    ),
    insecure: bool = typer.Option(
        False, "--insecure", "-k", help="Skip TLS certificate verification on https targets."
    ),
    json_out: Path | None = typer.Option(
        None, help="Optional machine-readable full report (JSONL)."
    ),
    fail_on: str = typer.Option("none", help="CI gate: none|low|medium|high|critical."),
    min_confidence: float = typer.Option(
        0.0, help="Drop findings below this confidence (0.0–1.0; 0 keeps all)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Console detail; never changes file output."
    ),
) -> None:
    """Audit a GraphQL endpoint against the OWASP GraphQL Cheat Sheet."""
    try:
        role_list = load_roles(roles) if roles is not None else default_roles()
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(2) from exc

    fail_on_norm = fail_on.strip().lower()
    if fail_on_norm not in ("none", "low", "medium", "high", "critical"):
        console.print(f"[red]config error:[/red] invalid --fail-on: {fail_on!r}")
        raise typer.Exit(2)

    if schema is not None and not schema.exists():
        console.print(f"[red]config error:[/red] schema file not found: {schema}")
        raise typer.Exit(2)

    settings = Settings(
        url=url,
        roles=role_list,
        schema_path=schema,
        findings_out=findings_out,
        matrix_out=matrix_out,
        json_out=json_out,
        checks=_split_list(checks),
        skip=_split_list(skip) or [],
        allow_mutations=allow_mutations,
        timeout=timeout,
        max_depth=max_depth,
        rps=rps,
        proxy=proxy,
        insecure=insecure,
        fail_on=fail_on_norm,
        min_confidence=min_confidence,
        verbose=verbose,
    )

    reporter = Reporter(console, verbose=verbose)
    with Transport(timeout=timeout, rps=rps, proxy=proxy, insecure=insecure) as transport:
        result = run_scan(settings, transport, reporter)

    if not result.target_reachable:
        console.print(f"[red]target unreachable:[/red] {url}")
        raise typer.Exit(3)

    write_findings_csv(result.findings, findings_out)
    write_matrix_csv(result.matrix, matrix_out)
    if json_out is not None:
        write_jsonl(result, json_out, url=url)

    _print_summary(result, settings)

    if fail_on_norm != "none":
        threshold = Severity.from_label(fail_on_norm)
        if any(f.severity >= threshold for f in result.findings):
            raise typer.Exit(1)
    raise typer.Exit(0)


def _print_summary(result: object, settings: Settings) -> None:
    from .engine import ScanResult

    assert isinstance(result, ScanResult)
    # Findings are streamed live by the Reporter during the scan; here we only
    # point at the written artifacts.
    console.print(f"  findings  →  {settings.findings_out}")
    console.print(f"  access matrix ({len(result.matrix.operations)} ops)  →  {settings.matrix_out}")
    if settings.verbose and result.skipped_checks:
        console.print(f"  skipped checks: {', '.join(result.skipped_checks)}")


def main() -> None:  # console-script convenience; typer app is the entry point.
    app()


if __name__ == "__main__":
    sys.exit(app())
