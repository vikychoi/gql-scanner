"""Per-role credential sessions with on-expiry refresh.

A :class:`SessionManager` holds the *current* credentials for each role and knows
how to refresh them when a response indicates the session expired (§ token
maintenance). Refresh sources (configured per role via ``RefreshSpec``):

* ``script`` — run as a subprocess; by default via ``uv run --with <deps>`` so the
  script's dependencies (e.g. ``requests``) are guaranteed in an isolated env,
  independent of how gql-scanner itself was installed (incl. ``uvx``).
* ``command`` — an arbitrary shell command (you control the interpreter/env).
* ``entrypoint`` — an in-process ``"module:function"`` callable (trusted; deps must
  be in gql-scanner's own environment).

The source emits either a bare token (applied via ``inject_header``/template) or a
JSON object ``{"headers": {...}, "cookies": {...}}``.

Refresh is driven by an expiry signal, both proactively and reactively:

* :meth:`SessionManager.prime` baselines every credentialed role up front with a
  minimal ``{ __typename }`` probe and refreshes a stale token before the scan.
* Any authenticated request that comes back expired refreshes + replays once.

Refresh is uncapped across a scan (a verified response resets the budget) but stops
after ``_MAX_CONSECUTIVE_REFRESH`` consecutive non-productive refreshes, so a token
that is itself immediately rejected is reported as unauthorized rather than retried
forever.
"""

from __future__ import annotations

import importlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import RefreshSpec, Role
from .exchange import Exchange
from .heuristics import looks_like_session_expired
from .transport import Transport


class RefreshError(Exception):
    """Raised when a credential refresh cannot produce usable credentials."""


@dataclass
class Credentials:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def merged_headers(self) -> dict[str, str] | None:
        return dict(self.headers) if self.headers else None

    def merged_cookies(self) -> dict[str, str] | None:
        return dict(self.cookies) if self.cookies else None


def _parse_output(spec: RefreshSpec, raw: str) -> Credentials:
    """Interpret refresh output: a JSON {headers,cookies} object, or a bare token."""
    text = raw.strip()
    if not text:
        raise RefreshError("refresh produced no output")
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict) and ("headers" in obj or "cookies" in obj):
        headers = {str(k): str(v) for k, v in (obj.get("headers") or {}).items()}
        cookies = {str(k): str(v) for k, v in (obj.get("cookies") or {}).items()}
        return Credentials(headers=headers, cookies=cookies)
    # Bare token → apply via the configured header template.
    token = text
    return Credentials(headers={spec.inject_header: spec.inject_template.format(token=token)})


def _build_argv(spec: RefreshSpec) -> list[str]:
    if spec.command:
        return shlex.split(spec.command)
    assert spec.script is not None
    if spec.runner:
        return [*shlex.split(spec.runner), spec.script]
    # Default: prefer `uv run` so PEP 723 / --with dependencies are guaranteed in an
    # isolated env; fall back to gql-scanner's own interpreter if uv isn't available.
    if shutil.which("uv"):
        argv = ["uv", "run"]
        for dep in spec.dependencies:
            argv += ["--with", dep]
        argv.append(spec.script)
        return argv
    return [sys.executable, spec.script]


def run_refresh(spec: RefreshSpec, *, role: str, url: str, old_token: str) -> Credentials:
    """Execute a refresh source and return new credentials."""
    if spec.entrypoint:
        module_name, _, func_name = spec.entrypoint.partition(":")
        if not func_name:
            raise RefreshError(f"entrypoint must be 'module:function', got {spec.entrypoint!r}")
        try:
            module = importlib.import_module(module_name)
            func: Callable[[dict[str, str]], object] = getattr(module, func_name)
        except (ImportError, AttributeError) as exc:
            raise RefreshError(f"cannot load entrypoint {spec.entrypoint!r}: {exc}") from exc
        result = func({"role": role, "url": url, "old_token": old_token})
        if isinstance(result, dict):
            return _parse_output(spec, json.dumps(result))
        return _parse_output(spec, str(result))

    argv = _build_argv(spec)
    env = {
        **os.environ,
        "GQLSCAN_ROLE": role,
        "GQLSCAN_URL": url,
        "GQLSCAN_OLD_TOKEN": old_token,
    }
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=spec.timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RefreshError(f"refresh command failed to run: {exc}") from exc
    if proc.returncode != 0:
        raise RefreshError(
            f"refresh command exited {proc.returncode}: {proc.stderr.strip()[:200]}"
        )
    return _parse_output(spec, proc.stdout)


# Refresh whenever creds look expired, but never spin on a token that is itself
# immediately rejected: after this many *consecutive* non-productive refreshes (a
# freshly-minted token that still looks expired) we stop and treat the role as
# unauthorized. A verified (non-expired) response resets the counter, so a long scan
# can refresh again whenever creds genuinely re-expire. Fixed constant (§9.3).
_MAX_CONSECUTIVE_REFRESH = 3

# Minimal, schema-independent liveness probe for the baseline credential check:
# ``__typename`` resolves on any GraphQL endpoint without hitting a data resolver.
_BASELINE_PROBE = "query { __typename }"


class SessionManager:
    """Tracks current credentials per role and refreshes them on expiry.

    Refresh is gated on a real expiry signal (:func:`looks_like_session_expired`) and
    is otherwise uncapped across the scan: any authenticated request — or the up-front
    baseline (:meth:`prime`) — that comes back ``401`` / ``UNAUTHENTICATED`` / expired
    triggers a refresh + replay. The only brake is ``_MAX_CONSECUTIVE_REFRESH``
    consecutive non-productive refreshes, after which the role is treated as
    unauthorized rather than refreshed again.
    """

    def __init__(self, roles: list[Role], url: str, reporter: object | None = None) -> None:
        self._url = url
        self._reporter = reporter
        self._roles = {r.name: r for r in roles}
        self._creds = {
            r.name: Credentials(headers=dict(r.headers), cookies=dict(r.cookies)) for r in roles
        }
        self._exhausted: set[str] = set()  # roles we have given up refreshing
        self._consecutive_failures: dict[str, int] = {}  # non-productive refreshes in a row

    def creds(self, role_name: str) -> Credentials:
        return self._creds.get(role_name, Credentials())

    def _token_of(self, role_name: str) -> str:
        role = self._roles.get(role_name)
        spec = role.refresh if role else None
        header = spec.inject_header if spec else "Authorization"
        return self.creds(role_name).headers.get(header, "")

    def _can_attempt_refresh(self, role_name: str) -> bool:
        role = self._roles.get(role_name)
        return role is not None and role.refresh is not None and role_name not in self._exhausted

    def refresh(self, role_name: str) -> bool:
        """Run a role's refresh source once, updating its creds in place.

        Returns True only when the source produced credentials. A source error marks
        the role exhausted so it is never retried.
        """
        if not self._can_attempt_refresh(role_name):
            return False
        spec = self._roles[role_name].refresh
        assert spec is not None  # guaranteed by _can_attempt_refresh
        try:
            new = run_refresh(
                spec, role=role_name, url=self._url, old_token=self._token_of(role_name)
            )
        except RefreshError as exc:
            self._exhausted.add(role_name)
            self._note(f"[yellow]![/yellow] refresh failed for role '{role_name}': {exc}")
            return False
        cur = self._creds[role_name]
        cur.headers.update(new.headers)
        cur.cookies.update(new.cookies)
        self._note(f"[green]↻[/green] refreshed credentials for role '{role_name}'")
        return True

    def _execute(
        self,
        transport: Transport,
        role_name: str,
        document: str,
        *,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> Exchange:
        """Send a GraphQL op as a role, refreshing + replaying once on session expiry."""

        def send() -> Exchange:
            creds = self.creds(role_name)
            return transport.graphql(
                self._url,
                document,
                headers=creds.merged_headers(),
                cookies=creds.merged_cookies(),
                variables=variables,
                operation_name=operation_name,
            )

        ex = send()
        if not looks_like_session_expired(ex):
            self._consecutive_failures[role_name] = 0  # creds verified working
            return ex
        if not self._can_attempt_refresh(role_name) or not self.refresh(role_name):
            return ex
        ex = send()  # replay with the refreshed credentials
        if not looks_like_session_expired(ex):
            self._consecutive_failures[role_name] = 0
            return ex
        # A freshly-minted token is still rejected: unauthorized, not expiry.
        self._consecutive_failures[role_name] = self._consecutive_failures.get(role_name, 0) + 1
        if self._consecutive_failures[role_name] >= _MAX_CONSECUTIVE_REFRESH:
            self._exhausted.add(role_name)
            self._note(
                f"[yellow]![/yellow] role '{role_name}' still rejected after "
                f"{_MAX_CONSECUTIVE_REFRESH} refreshes → treating as unauthorized"
            )
        else:
            self._note(
                f"[yellow]![/yellow] refreshed but role '{role_name}' still rejected "
                "→ treating as unauthorized"
            )
        return ex

    def graphql(
        self,
        transport: Transport,
        role_name: str,
        document: str,
        *,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> Exchange:
        """Refresh-aware single GraphQL operation sent as ``role_name``."""
        return self._execute(
            transport, role_name, document, variables=variables, operation_name=operation_name
        )

    def request(self, transport: Transport, role_name: str, document: str) -> Exchange:
        """Backwards-compatible alias for :meth:`graphql` (used by the access matrix)."""
        return self._execute(transport, role_name, document)

    def prime(self, transport: Transport) -> None:
        """Baseline each credentialed role up front and refresh stale tokens proactively.

        Sends a minimal ``{ __typename }`` probe as every role that carries
        credentials; an expiry signal triggers the same refresh + replay path as a
        live request. Roles with no credentials (e.g. ``unauthenticated``) are skipped.
        Catching a stale token here means the whole scan runs on fresh credentials
        instead of rediscovering the expiry operation-by-operation.

        Caveat: a server that enforces auth per-resolver (not globally) may answer
        ``{ __typename }`` without checking the token, so the baseline can read "OK"
        for an expired session; the reactive refresh on the first guarded operation is
        the safety net for that case.
        """
        for role_name in sorted(self._roles):
            creds = self.creds(role_name)
            if not creds.headers and not creds.cookies:
                continue  # nothing to validate (unauthenticated)
            ex = self._execute(transport, role_name, _BASELINE_PROBE)
            if not looks_like_session_expired(ex):
                self._note(f"baseline: role '{role_name}' credentials OK")
            elif self._roles[role_name].refresh is None:
                self._note(
                    f"[yellow]![/yellow] baseline: role '{role_name}' token appears expired "
                    "and no refresh is configured — results may be unreliable"
                )
            # else: _execute already attempted a refresh and noted the outcome.

    def _note(self, message: str) -> None:
        phase = getattr(self._reporter, "phase", None)
        if callable(phase):
            phase(message)
