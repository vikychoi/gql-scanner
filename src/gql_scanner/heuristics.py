"""Centralized, named heuristics. No magic strings scattered across checks.

Every fuzzy decision the scanner makes — "is this an authorization denial?",
"does this look like a stack trace?", "did the server interpret my injection
canary?" — lives here as a small pure function over an :class:`Exchange`, so the
behavior is auditable and deterministic.
"""

from __future__ import annotations

import re
from enum import StrEnum

from .exchange import Exchange

# --- Access classification (drives the access matrix, §10) -------------------

# GraphQL error extension codes that unambiguously mean "authorization denied".
_AUTHZ_CODES = {
    "UNAUTHENTICATED",
    "UNAUTHORIZED",
    "FORBIDDEN",
    "ACCESS_DENIED",
    "PERMISSION_DENIED",
}

# Substrings in error messages that indicate an authorization denial (lowercased).
_AUTHZ_MESSAGE_MARKERS = (
    "not authorized",
    "unauthorized",
    "unauthenticated",
    "forbidden",
    "permission denied",
    "access denied",
    "must be logged in",
    "requires authentication",
    "not allowed",
    "insufficient",
)

# Substrings indicating a *validation* error (the op shape was wrong), not authz.
_VALIDATION_MARKERS = (
    "cannot query field",
    "unknown argument",
    "syntax error",
    "expected type",
    "did you mean",
    "must have a selection",
    "is required",
    "of required type",
)


class Access(StrEnum):
    """Access-matrix cell vocabulary (§8.2)."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_TESTED = "NOT_TESTED"


def _error_texts(exchange: Exchange) -> list[str]:
    texts: list[str] = []
    for err in exchange.graphql_errors():
        msg = err.get("message")
        if isinstance(msg, str):
            texts.append(msg.lower())
    return texts


def _error_codes(exchange: Exchange) -> set[str]:
    codes: set[str] = set()
    for err in exchange.graphql_errors():
        ext = err.get("extensions")
        if isinstance(ext, dict):
            code = ext.get("code")
            if isinstance(code, str):
                codes.add(code.upper())
    return codes


def is_authz_denied(exchange: Exchange) -> bool:
    """True when the response signals an authorization denial."""
    if exchange.status in (401, 403):
        return True
    if _error_codes(exchange) & _AUTHZ_CODES:
        return True
    return any(
        marker in text for text in _error_texts(exchange) for marker in _AUTHZ_MESSAGE_MARKERS
    )


def is_validation_error(exchange: Exchange) -> bool:
    """True when errors look like query-shape/validation problems, not authz."""
    return any(marker in text for text in _error_texts(exchange) for marker in _VALIDATION_MARKERS)


def classify_access(exchange: Exchange) -> Access:
    """Classify one operation probe into the access-matrix vocabulary.

    ``ALLOWED`` only when data resolved without an authorization error; authz
    errors → ``DENIED``; transport/5xx/validation noise → ``ERROR``.
    """
    if not exchange.ok or exchange.status == 0:
        return Access.ERROR
    if exchange.status >= 500:
        return Access.ERROR
    if is_authz_denied(exchange):
        return Access.DENIED
    data = exchange.graphql_data()
    if isinstance(data, dict):
        # data present with the field resolved to a non-null value => allowed.
        resolved = any(v is not None for v in data.values())
        if resolved:
            return Access.ALLOWED
        # data echoed but all-null with errors => most likely authz/validation.
        if exchange.graphql_errors():
            return Access.DENIED if not is_validation_error(exchange) else Access.ERROR
        # all-null, no errors: the field exists but returned null (allowed access).
        return Access.ALLOWED
    if exchange.graphql_errors():
        return Access.ERROR
    return Access.ERROR


# --- Configuration / error-handling signals (§7.1) ---------------------------

_STACK_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "at java.",
    "at org.",
    "at com.",
    ".java:",
    '.py", line',
    '\n  file "',
    "stack trace",
    "exception in thread",
    "goroutine ",
    "node_modules",
    "at object.<anonymous>",
    "syntaxerror:",
    "referenceerror:",
    "sequelize",
    "psycopg2",
    "sqlalchemy",
)

_GRAPHIQL_MARKERS = (
    "graphiql",
    "graphql playground",
    "playground-html",
    "<title>playground",
    "apollo sandbox",
    "embeddedsandbox",
    "graphql voyager",
)


def looks_like_stack_trace(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _STACK_TRACE_MARKERS)


def looks_like_graphql_ide(exchange: Exchange) -> bool:
    body = exchange.response_body.lower()
    ctype = ""
    for line in exchange.raw_response.split("\r\n"):
        if line.lower().startswith("content-type:"):
            ctype = line.split(":", 1)[1].strip().lower()
            break
    if "text/html" not in ctype and "<html" not in body:
        return False
    return any(m in body for m in _GRAPHIQL_MARKERS)


def field_suggestion(exchange: Exchange) -> str | None:
    """Return the matched 'Did you mean' suggestion text, if present."""
    for text in _error_texts(exchange):
        m = re.search(r"did you mean ([^?]*)", text)
        if m:
            return f"Did you mean {m.group(1).strip()}"
    return None


# --- Injection / input-validation signals (§7.5) -----------------------------

_DB_ERROR_MARKERS = (
    "sql syntax",
    "syntax error at or near",
    "unterminated quoted string",
    "sqlite3.",
    "ora-0",
    "mysql_",
    "you have an error in your sql",
    "pg::",
    "psql:",
    "mongoerror",
    "bsonerror",
    "unknown operator",
    "$where",
)

_OS_ERROR_MARKERS = (
    "sh: 1:",
    "/bin/sh",
    "command not found",
    "no such file or directory",
    "cannot execute",
)


def looks_like_db_error(exchange: Exchange) -> bool:
    low = exchange.response_body.lower()
    return any(m in low for m in _DB_ERROR_MARKERS)


def looks_like_os_error(exchange: Exchange) -> bool:
    low = exchange.response_body.lower()
    return any(m in low for m in _OS_ERROR_MARKERS)


_SSRF_MARKERS = (
    "connection refused",
    "econnrefused",
    "no route to host",
    "connect etimedout",
    "failed to connect",
    "dial tcp 127.0.0.1",
    "connection error",
    "getaddrinfo",
    "name or service not known",
)


def looks_like_ssrf_signal(exchange: Exchange) -> bool:
    """True when the response shows the server attempted an outbound fetch."""
    low = exchange.response_body.lower()
    return any(m in low for m in _SSRF_MARKERS)


def looks_like_nosql_signal(exchange: Exchange) -> bool:
    """True when NoSQL-operator input was *interpreted* (operator/Mongo errors).

    Scans error *messages* only, not the whole body — otherwise a reflected
    ``{"$ne": ...}`` payload echoed back in an id field would false-positive. The
    markers chosen are server-side errors that our payloads never contain
    verbatim.
    """
    markers = (
        "unknown operator",
        "mongoerror",
        "bsonerror",
        "cast to objectid",
        "must be an object",
        "$where",
    )
    return any(m in text for text in _error_texts(exchange) for m in markers)


# --- DoS / limit signals (§7.3) ----------------------------------------------

_LIMIT_REJECTION_MARKERS = (
    "query is too complex",
    "exceeds maximum",
    "maximum query depth",
    "query depth",
    "too deep",
    "depth limit",
    "complexity",
    "cost limit",
    "exceeds the maximum",
    "too many",
    "rate limit",
    "request too large",
)


def looks_like_limit_rejection(exchange: Exchange) -> bool:
    """True when the server rejected a query for depth/complexity/amount/rate."""
    if exchange.status in (413, 429):
        return True
    for text in _error_texts(exchange):
        if any(m in text for m in _LIMIT_REJECTION_MARKERS):
            return True
    return False


def executed_ok(exchange: Exchange) -> bool:
    """True when the query executed and returned data (no rejection, no error-only)."""
    if not exchange.ok or exchange.status != 200:
        return False
    if looks_like_limit_rejection(exchange):
        return False
    data = exchange.graphql_data()
    return isinstance(data, dict) and any(v is not None for v in data.values())


def batch_executed_count(exchange: Exchange) -> int:
    """For an array-batch response, count how many results came back."""
    body = exchange.json_body()
    if isinstance(body, list):
        return len(body)
    return 0
