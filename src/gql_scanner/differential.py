"""Baseline→mutate→compare machinery and confidence scoring.

Sophisticated detection is *differential*: send a baseline request, send a probe
that changes one variable, and compare structured fingerprints of the two
responses. A single boolean marker (``"sql syntax" in body``) is fragile; a
divergence in result count, error code, response size, or a reflected canary is
evidence. Multiple weak signals combine (noisy-OR) into a confidence score.

Everything here is deterministic: fingerprints are pure functions of the
response, timing uses a fixed repeat count + median + absolute threshold, and no
time value ever reaches a finding's evidence or sort key (§9.6).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .exchange import Exchange

# Timing: fixed repeats + median keeps blind/time-based signals reproducible.
TIMING_REPEATS = 3
# A probe is "slow" only if its median is both a large multiple of baseline AND
# over an absolute floor — avoids flagging sub-millisecond jitter.
TIMING_RATIO = 3.0
TIMING_FLOOR_MS = 1500


@dataclass(frozen=True)
class Signal:
    """One piece of evidence contributing to a finding's confidence."""

    name: str
    weight: float  # independent probability-of-true in [0, 1]
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.name}({self.weight:.2f}){f': {self.detail}' if self.detail else ''}"


def combine_confidence(signals: tuple[Signal, ...]) -> float:
    """Noisy-OR combination: confidence = 1 - ∏(1 - wᵢ). Bounded, monotonic."""
    prod = 1.0
    for s in signals:
        w = min(max(s.weight, 0.0), 1.0)
        prod *= 1.0 - w
    return round(1.0 - prod, 4)


@dataclass(frozen=True)
class Fingerprint:
    """A comparable, structural summary of a GraphQL HTTP response."""

    status: int
    error_codes: tuple[str, ...]
    error_count: int
    has_data: bool
    result_count: int  # items in the first list found in data; -1 if none
    body_size: int
    data_shape: str  # structural hash of the data tree (keys/types, not values)
    transport_error: bool

    def differs_from(self, other: Fingerprint) -> bool:
        return (
            self.status != other.status
            or self.error_codes != other.error_codes
            or self.result_count != other.result_count
            or self.data_shape != other.data_shape
        )


def _first_list_count(node: Any) -> int:
    """Count items in the first list encountered in a depth-first walk; -1 if none."""
    if isinstance(node, list):
        return len(node)
    if isinstance(node, dict):
        for key in sorted(node):
            n = _first_list_count(node[key])
            if n >= 0:
                return n
    return -1


def _shape(node: Any) -> str:
    """Structural signature of a JSON value: keys and value *types*, not values."""
    if isinstance(node, dict):
        return "{" + ",".join(f"{k}:{_shape(node[k])}" for k in sorted(node)) + "}"
    if isinstance(node, list):
        head = _shape(node[0]) if node else ""
        return f"[{head}]"
    if node is None:
        return "null"
    return type(node).__name__


def data_shape(data: Any) -> str:
    return hashlib.sha1(_shape(data).encode()).hexdigest()[:16]


def fingerprint(exchange: Exchange) -> Fingerprint:
    """Reduce a response to a comparable :class:`Fingerprint`."""
    codes: list[str] = []
    for err in exchange.graphql_errors():
        ext = err.get("extensions")
        if isinstance(ext, dict) and isinstance(ext.get("code"), str):
            codes.append(ext["code"].upper())
    data = exchange.graphql_data()
    return Fingerprint(
        status=exchange.status,
        error_codes=tuple(sorted(codes)),
        error_count=len(exchange.graphql_errors()),
        has_data=isinstance(data, (dict, list)),
        result_count=_first_list_count(data),
        body_size=len(exchange.response_body),
        data_shape=data_shape(data) if data is not None else "",
        transport_error=not exchange.ok,
    )


def reflected(exchange: Exchange, canary: str) -> bool:
    """True if the canary marker appears in the (data portion of the) response."""
    data = exchange.graphql_data()
    if data is None:
        return canary in exchange.response_body
    import json

    return canary in json.dumps(data)


def median_elapsed_ms(
    send: Callable[[], Exchange], repeats: int = TIMING_REPEATS
) -> tuple[Exchange, int]:
    """Send ``repeats`` times, returning the last exchange and the median latency."""
    samples: list[int] = []
    last: Exchange | None = None
    for _ in range(repeats):
        last = send()
        samples.append(last.elapsed_ms)
    samples.sort()
    assert last is not None
    return last, samples[len(samples) // 2]


def time_delay_signal(baseline_ms: int, probe_ms: int) -> Signal | None:
    """A conservative blind/time-based signal (no ms value in detail — §9.6)."""
    if probe_ms >= TIMING_FLOOR_MS and probe_ms >= baseline_ms * TIMING_RATIO:
        return Signal("time-delay", 0.5, "probe response markedly slower than baseline")
    return None


@dataclass
class DiffResult:
    """Outcome of a differential probe, ready to become a Finding if confident."""

    signals: tuple[Signal, ...] = ()
    evidence: str = ""
    probe_exchange: Exchange | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        return combine_confidence(self.signals)

    def signal_summary(self) -> str:
        return "; ".join(str(s) for s in self.signals)
