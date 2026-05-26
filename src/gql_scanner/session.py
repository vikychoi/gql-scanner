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
JSON object ``{"headers": {...}, "cookies": {...}}``. Refresh runs lazily: once on
first expiry, then the failed request is replayed with the new credentials.
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


class SessionManager:
    """Tracks current credentials per role and refreshes them on expiry."""

    def __init__(self, roles: list[Role], url: str, reporter: object | None = None) -> None:
        self._url = url
        self._reporter = reporter
        self._roles = {r.name: r for r in roles}
        self._creds = {
            r.name: Credentials(headers=dict(r.headers), cookies=dict(r.cookies)) for r in roles
        }
        self._exhausted: set[str] = set()  # roles whose refresh already failed

    def creds(self, role_name: str) -> Credentials:
        return self._creds.get(role_name, Credentials())

    def _token_of(self, role_name: str) -> str:
        spec = self._roles[role_name].refresh
        header = spec.inject_header if spec else "Authorization"
        return self.creds(role_name).headers.get(header, "")

    def refresh(self, role_name: str) -> bool:
        """Refresh a role's credentials in place. Returns True on success."""
        role = self._roles.get(role_name)
        if role is None or role.refresh is None or role_name in self._exhausted:
            return False
        try:
            new = run_refresh(
                role.refresh,
                role=role_name,
                url=self._url,
                old_token=self._token_of(role_name),
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

    def request(self, transport: Transport, role_name: str, document: str) -> Exchange:
        """Send a GraphQL op as a role, refreshing+replaying once on session expiry."""
        creds = self.creds(role_name)
        ex = transport.graphql(
            self._url, document, headers=creds.merged_headers(), cookies=creds.merged_cookies()
        )
        if (
            looks_like_session_expired(ex)
            and self._roles.get(role_name, Role(name=role_name)).refresh is not None
            and self.refresh(role_name)
        ):
            creds = self.creds(role_name)
            ex = transport.graphql(
                self._url, document, headers=creds.merged_headers(), cookies=creds.merged_cookies()
            )
        return ex

    def _note(self, message: str) -> None:
        phase = getattr(self._reporter, "phase", None)
        if callable(phase):
            phase(message)
