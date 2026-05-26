"""Finding model, severity ordering, and stable finding identity."""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

_ROOT_FIELD = re.compile(
    r"\b(?:query|mutation|subscription)\b[^{]*\{\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_]\w*)"
)
_SHORTHAND = re.compile(r"^\s*\{\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_]\w*)")


def _document_from_raw(raw_request: str) -> str:
    """Pull the GraphQL document out of a raw HTTP request (POST body or GET ?query)."""
    head, sep, body = raw_request.partition("\r\n\r\n")
    if sep and body.strip().startswith("{"):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict) and isinstance(obj.get("query"), str):
                return str(obj["query"])
        except (json.JSONDecodeError, ValueError):
            pass
    request_line = head.split("\r\n", 1)[0]
    parts = request_line.split(" ")
    if len(parts) >= 2 and "?" in parts[1]:
        qs = parse_qs(urlparse(parts[1]).query)
        if "query" in qs:
            return unquote(qs["query"][0])
    return ""


def derive_operation(raw_request: str) -> str:
    """Best-effort root operation name for the findings CSV (no raw blobs there)."""
    doc = _document_from_raw(raw_request)
    if not doc:
        return ""
    m = _ROOT_FIELD.search(doc) or _SHORTHAND.search(doc)
    return str(m.group(1)) if m else ""


class Severity(enum.IntEnum):
    """Ordered severities. Higher value == more severe (used for sorting)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> Severity:
        return cls[label.strip().upper()]


@dataclass(frozen=True)
class Finding:
    """A single security finding, carrying everything needed to reproduce it."""

    check_id: str
    issue_name: str
    description: str
    severity: Severity
    raw_request: str
    raw_response: str
    remediation: str
    evidence: str = ""
    confidence: float = 1.0  # noisy-OR of corroborating signals, in [0, 1]
    signals: str = ""  # human-readable signal summary (also in JSONL)
    operation: str = ""  # the query/mutation name the finding concerns (for the CSV)
    # Free-form structured extras for the JSONL report only (never CSV).
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def dedupe_key(self) -> tuple[str, str]:
        """Identity for de-duplication: check_id + normalized evidence."""
        return (self.check_id, self.evidence.strip())

    def with_derived_operation(self) -> Finding:
        """Return a copy with ``operation`` filled in from the raw request if empty."""
        if self.operation:
            return self
        from dataclasses import replace

        return replace(self, operation=derive_operation(self.raw_request))

    @property
    def sort_key(self) -> tuple[int, str, str]:
        """Sort by severity desc, then check_id asc, then evidence asc.

        Confidence is deliberately not part of the key: it varies with
        corroborating signals and must not perturb deterministic row order.
        """
        return (-int(self.severity), self.check_id, self.evidence)


def finalize_findings(findings: list[Finding], min_confidence: float = 0.0) -> list[Finding]:
    """Dedupe, confidence-filter, fill ``operation``, and sort into the output order.

    The single source of truth for findings-CSV row order, shared by the engine's
    final result and the incremental writer so a partial (interrupted) CSV is ordered
    and de-duplicated exactly like a completed one. Sort is (severity desc, check_id
    asc, evidence asc) per §8.1; confidence never perturbs the order (§9).
    """
    seen: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.dedupe_key in seen:
            continue
        seen.add(f.dedupe_key)
        deduped.append(f)
    if min_confidence > 0.0:
        deduped = [f for f in deduped if f.confidence >= min_confidence]
    deduped = [f.with_derived_operation() for f in deduped]
    deduped.sort(key=lambda f: f.sort_key)
    return deduped
