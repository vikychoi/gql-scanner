"""Precision/recall over the labeled corpus — quantitative accuracy guardrails."""

from __future__ import annotations

import pytest

from conftest import ScanFn
from corpus import PROFILES, score


def _fired(result: object) -> set[str]:
    return {f.check_id for f in result.findings}  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_perfect_recall(scan: ScanFn, name: str) -> None:
    """Every labeled-true vulnerability is detected (no false negatives)."""
    module, expected, opts = PROFILES[name]
    result = scan(module, **opts)
    metrics = score(_fired(result), expected)
    assert metrics.false_negatives == 0, (
        f"{name}: missed {expected - _fired(result)}"
    )
    assert metrics.recall == 1.0


def test_hardened_has_no_false_positives(scan: ScanFn) -> None:
    """A correctly-hardened target must produce zero findings (precision = 1)."""
    module, expected, opts = PROFILES["hardened"]
    fired = _fired(scan(module, **opts))
    assert fired == set(), f"false positives on hardened: {fired}"


def test_partial_precision(scan: ScanFn) -> None:
    """The defended-but-leaky target yields only the two real schema-leak findings."""
    module, expected, opts = PROFILES["partial"]
    fired = _fired(scan(module, **opts))
    metrics = score(fired, expected)
    assert metrics.false_positives == 0, f"unexpected findings: {fired - expected}"
    assert metrics.precision == 1.0


def test_confidence_is_bounded(scan: ScanFn, vuln: object) -> None:
    """Every finding carries a confidence in [0, 1]."""
    for f in scan(vuln, allow_mutations=True).findings:
        assert 0.0 <= f.confidence <= 1.0
