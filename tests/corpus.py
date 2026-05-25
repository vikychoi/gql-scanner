"""Labeled corpus + precision/recall metrics for the mock targets.

Each profile is labeled with the set of check IDs that *should* fire against it
(ground truth). The harness compares the scanner's actual findings to the labels
and reports precision/recall, so a heuristic change that adds false positives or
drops a true positive is caught quantitatively — not just "did this one check
fire".
"""

from __future__ import annotations

from dataclasses import dataclass

from mock_server import hardened, partial, vulnerable

# Checks expected to fire against the fully-vulnerable target (with --allow-mutations).
# Excluded: GQL-DIRECTIVE-OVERLOAD (graphql-core rejects duplicate directives),
# GQL-INJECTION-TEMPLATE (mock does not evaluate templates), GQL-AUTH-BATCH (no
# auth-named mutation in the mock schema), GQL-SCHEMA-RECONSTRUCTED (introspection
# is on, so no reconstruction needed).
VULNERABLE_EXPECTED = {
    "GQL-INTROSPECTION-ENABLED",
    "GQL-GRAPHIQL-EXPOSED",
    "GQL-EXCESSIVE-ERRORS",
    "GQL-FIELD-SUGGESTIONS",
    "GQL-NODE-FIELD-ACCESS",
    "GQL-BOLA-IDOR",
    "GQL-BFLA",
    "GQL-UNAUTH-ACCESS",
    "GQL-EDGE-NODE-AUTHZ",
    "GQL-DEPTH-LIMIT",
    "GQL-AMOUNT-LIMIT",
    "GQL-PAGINATION",
    "GQL-QUERY-COST",
    "GQL-TIMEOUT",
    "GQL-ARRAY-BATCHING",
    "GQL-ALIAS-BATCHING",
    "GQL-BATCH-RATE-LIMIT",
    "GQL-CSRF-GET",
    "GQL-CORS",
    "GQL-INJECTION-SQL",
    "GQL-INJECTION-NOSQL",
    "GQL-INJECTION-OS",
    "GQL-INJECTION-SSRF",
    "GQL-INPUT-ALLOWLIST",
}

# A correctly-hardened target should yield zero findings.
HARDENED_EXPECTED: set[str] = set()

# The partial target leaks only its schema (introspection + suggestions on);
# everything else is properly defended.
PARTIAL_EXPECTED = {"GQL-INTROSPECTION-ENABLED", "GQL-FIELD-SUGGESTIONS"}

PROFILES = {
    "vulnerable": (vulnerable, VULNERABLE_EXPECTED, {"allow_mutations": True}),
    "hardened": (hardened, HARDENED_EXPECTED, {}),
    "partial": (partial, PARTIAL_EXPECTED, {}),
}


@dataclass(frozen=True)
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return 1.0 if denom == 0 else self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return 1.0 if denom == 0 else self.true_positives / denom


def score(fired: set[str], expected: set[str]) -> Metrics:
    return Metrics(
        true_positives=len(fired & expected),
        false_positives=len(fired - expected),
        false_negatives=len(expected - fired),
    )
