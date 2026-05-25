"""The single place that touches the network.

Wraps a synchronous ``httpx.Client`` and captures the *actual* bytes of every
request/response so findings can be replayed verbatim. Client-side request
pacing (``--rps``) is enforced here deterministically.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .exchange import Exchange


def _format_request(request: httpx.Request) -> str:
    """Reconstruct the verbatim HTTP request from the real ``httpx.Request``."""
    target = request.url.raw_path.decode("ascii", "replace")
    lines = [f"{request.method} {target} HTTP/1.1"]
    for name, value in request.headers.items():
        lines.append(f"{name}: {value}")
    body = request.content.decode("utf-8", "replace")
    return "\r\n".join(lines) + "\r\n\r\n" + body


# Response headers whose values vary with wall-clock time; normalized in the
# captured raw response so two scans of an unchanged target diff byte-identically
# (§9.4). They are response-side metadata, irrelevant to replaying the request.
_VOLATILE_RESPONSE_HEADERS = {"date"}
_NORMALIZED = "<normalized-by-gql_scanner>"


def _format_response(response: httpx.Response) -> str:
    """Reconstruct the verbatim HTTP response from the real ``httpx.Response``.

    Time-varying response headers (e.g. ``Date``) are normalized to a fixed token
    to keep CSV output deterministic; everything else is captured verbatim.
    """
    version = response.http_version or "HTTP/1.1"
    lines = [f"{version} {response.status_code} {response.reason_phrase}"]
    for name, value in response.headers.items():
        if name.lower() in _VOLATILE_RESPONSE_HEADERS:
            value = _NORMALIZED
        lines.append(f"{name}: {value}")
    body = response.text
    return "\r\n".join(lines) + "\r\n\r\n" + body


class Transport:
    """Deterministic HTTP transport with verbatim capture and client-side pacing."""

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        rps: float = 5.0,
        proxy: str | None = None,
        insecure: bool = False,
    ) -> None:
        self._min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._last_sent = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            verify=not insecure,
            proxy=proxy,
            follow_redirects=False,
            headers={"User-Agent": "gql-scanner/0.1"},
        )

    def __enter__(self) -> Transport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _pace(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_sent
        wait = self._min_interval - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_sent = time.monotonic()

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        json: Any = None,
        content: bytes | None = None,
    ) -> Exchange:
        """Send one request and return a verbatim :class:`Exchange`.

        Transport-level failures (DNS, connect, timeout, TLS) are captured as an
        ``Exchange`` with ``status=0`` and ``transport_error`` set — never raised.
        """
        self._pace()
        request = self._client.build_request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            json=json,
            content=content,
        )
        raw_request = _format_request(request)
        start = time.monotonic()
        try:
            response = self._client.send(request)
        except httpx.HTTPError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return Exchange(
                raw_request=raw_request,
                raw_response="",
                method=method,
                url=url,
                status=0,
                elapsed_ms=elapsed_ms,
                transport_error=f"{type(exc).__name__}: {exc}",
            )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return Exchange(
            raw_request=raw_request,
            raw_response=_format_response(response),
            method=method,
            url=url,
            status=response.status_code,
            elapsed_ms=elapsed_ms,
        )

    def graphql(
        self,
        url: str,
        query: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> Exchange:
        """POST a single GraphQL operation."""
        payload: dict[str, Any] = {"query": query}
        if variables is not None:
            payload["variables"] = variables
        if operation_name is not None:
            payload["operationName"] = operation_name
        merged = {"Content-Type": "application/json", **(headers or {})}
        return self.send("POST", url, headers=merged, cookies=cookies, json=payload)

    def graphql_batch(
        self,
        url: str,
        payload: list[dict[str, Any]],
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Exchange:
        """POST a JSON-array batch of GraphQL operations."""
        merged = {"Content-Type": "application/json", **(headers or {})}
        return self.send("POST", url, headers=merged, cookies=cookies, json=payload)
