"""Verbatim HTTP exchange record used to reproduce findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Exchange:
    """Verbatim record of one HTTP round trip, used to reproduce findings.

    ``raw_request`` and ``raw_response`` capture what actually went over the
    wire (request-line/status-line + headers + blank line + body) so a human can
    replay the issue with curl/Burp/Repeater.
    """

    raw_request: str
    raw_response: str
    method: str
    url: str
    status: int
    elapsed_ms: int
    # Parsed JSON body of the response, if it was valid JSON. ``None`` otherwise.
    # Kept off the verbatim record on purpose; checks use this for convenience.
    transport_error: str = ""

    @property
    def ok(self) -> bool:
        """True when the round trip completed without a transport-level error."""
        return not self.transport_error

    @property
    def response_body(self) -> str:
        """The response body (everything after the header/body separator)."""
        _, sep, body = self.raw_response.partition("\r\n\r\n")
        return body if sep else ""

    def response_header(self, name: str) -> str | None:
        """Case-insensitive lookup of a response header value, or None."""
        headers, _, _ = self.raw_response.partition("\r\n\r\n")
        target = name.lower()
        for line in headers.split("\r\n")[1:]:  # skip the status line
            key, sep, value = line.partition(":")
            if sep and key.strip().lower() == target:
                return value.strip()
        return None

    def json_body(self) -> Any:
        """Parse the response body as JSON, or return ``None`` if it isn't JSON."""
        try:
            return json.loads(self.response_body)
        except (json.JSONDecodeError, ValueError):
            return None

    def graphql_errors(self) -> list[dict[str, Any]]:
        """GraphQL top-level ``errors`` list, or empty if none/not JSON."""
        body = self.json_body()
        if isinstance(body, dict) and isinstance(body.get("errors"), list):
            return [e for e in body["errors"] if isinstance(e, dict)]
        return []

    def graphql_data(self) -> Any:
        """GraphQL top-level ``data``, or ``None``."""
        body = self.json_body()
        if isinstance(body, dict):
            return body.get("data")
        return None
