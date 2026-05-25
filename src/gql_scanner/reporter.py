"""Live progress reporting to the console (stderr only — never touches output files).

Modeled loosely on sqlmap's running commentary: phase lines, the check currently
running, the individual probe being sent (in ``--verbose``), and a coloured line
for each finding as it is discovered. All output is on stderr so stdout and the
CSV/JSONL artifacts stay clean and deterministic.
"""

from __future__ import annotations

from rich.console import Console

from .findings import Finding, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class Reporter:
    """Streams scan progress. A disabled reporter is a no-op (used in tests)."""

    def __init__(self, console: Console | None = None, *, verbose: bool = False,
                 enabled: bool = True) -> None:
        self._console = console or Console(stderr=True)
        self.verbose = verbose
        self.enabled = enabled

    def _print(self, text: str) -> None:
        if self.enabled:
            self._console.print(text, highlight=False)

    def banner(self, url: str) -> None:
        self._print(f"[bold]gql-scanner[/bold] scanning [cyan]{url}[/cyan]")

    def phase(self, message: str) -> None:
        self._print(f"[blue][*][/blue] {message}")

    def info(self, message: str) -> None:
        self._print(f"    {message}")

    def check_start(self, check_id: str, title: str) -> None:
        # The per-check header is verbose-only to keep the default output readable.
        if self.verbose:
            self._print(f"[blue][*][/blue] {check_id} — {title}")

    def probe(self, message: str) -> None:
        if self.verbose:
            self._print(f"    [dim]testing[/dim] {message}")

    def hit(self, finding: Finding) -> None:
        style = _SEV_STYLE.get(finding.severity, "white")
        sev = finding.severity.label.upper()
        where = f" [dim]({finding.operation})[/dim]" if finding.operation else ""
        self._print(
            f"[{style}][+][/{style}] [{style}]{sev:8}[/{style}] {finding.check_id}"
            f"{where}  conf={finding.confidence:.2f}  {finding.evidence}"
        )

    def check_result(self, check_id: str, n: int) -> None:
        if self.verbose and n == 0:
            self._print(f"    [dim]{check_id}: nothing found[/dim]")

    def summary(self, total: int) -> None:
        self._print(f"[blue][*][/blue] scan complete — [bold]{total}[/bold] finding(s)")
