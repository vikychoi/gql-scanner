"""Credential-refresh: expiry detection, subprocess refresh, retry, fail-safe."""

from __future__ import annotations

import json

import pytest

from gql_scanner.config import ConfigError, RefreshSpec, Role, load_roles
from gql_scanner.exchange import Exchange
from gql_scanner.session import _MAX_CONSECUTIVE_REFRESH, SessionManager, run_refresh


def _exchange(body: dict, status: int = 200) -> Exchange:
    return Exchange(
        raw_request="POST /graphql",
        raw_response=f"HTTP/1.1 {status} OK\r\n\r\n{json.dumps(body)}",
        method="POST",
        url="http://x/graphql",
        status=status,
        elapsed_ms=1,
    )


_EXPIRED = _exchange(
    {"errors": [{"message": "jwt expired", "extensions": {"code": "UNAUTHENTICATED"}}]}
)
_OK = _exchange({"data": {"me": {"email": "a@b.c"}}})


class _FakeTransport:
    """Returns expired for the stale token, data for a refreshed token."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def graphql(self, url, query, *, headers=None, cookies=None, **kw):  # type: ignore[no-untyped-def]
        token = (headers or {}).get("Authorization", "")
        self.calls.append(token)
        return _OK if token == "Bearer fresh" else _EXPIRED


def test_expiry_triggers_refresh_and_retry() -> None:
    role = Role(
        name="alice",
        headers={"Authorization": "Bearer stale"},
        refresh=RefreshSpec(command="printf fresh"),  # bare token -> "Bearer fresh"
    )
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    ex = sm.request(transport, "alice", "{ me { email } }")
    # The retried request used the refreshed token and returned data.
    assert ex.graphql_data() == {"me": {"email": "a@b.c"}}
    assert transport.calls == ["Bearer stale", "Bearer fresh"]
    assert sm.creds("alice").headers["Authorization"] == "Bearer fresh"


def test_no_refresh_without_spec() -> None:
    role = Role(name="bob", headers={"Authorization": "Bearer stale"})  # no refresh
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    ex = sm.request(transport, "bob", "{ me { email } }")
    assert ex is _EXPIRED  # stays expired, only one attempt, no refresh
    assert transport.calls == ["Bearer stale"]


def test_refresh_failure_is_safe() -> None:
    role = Role(
        name="alice",
        headers={"Authorization": "Bearer stale"},
        refresh=RefreshSpec(command="false"),  # exits non-zero -> RefreshError
    )
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    ex = sm.request(transport, "alice", "{ me { email } }")
    assert ex is _EXPIRED  # no crash; original (expired) response returned
    # A failed refresh is not retried again.
    assert sm.refresh("alice") is False


def test_refresh_json_headers_and_cookies() -> None:
    payload = json.dumps({"headers": {"Authorization": "Bearer J"}, "cookies": {"sid": "Z"}})
    creds = run_refresh(
        RefreshSpec(command=f"printf '{payload}'"), role="r", url="http://x", old_token=""
    )
    assert creds.headers == {"Authorization": "Bearer J"}
    assert creds.cookies == {"sid": "Z"}


# --- baseline (prime) + refresh policy --------------------------------------


def test_prime_refreshes_stale_token_proactively() -> None:
    role = Role(
        name="alice",
        headers={"Authorization": "Bearer stale"},
        refresh=RefreshSpec(command="printf fresh"),
    )
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    sm.prime(transport)
    # The baseline `{ __typename }` probe saw the stale token, refreshed, and the role
    # now carries fresh credentials before any real operation runs.
    assert sm.creds("alice").headers["Authorization"] == "Bearer fresh"
    assert transport.calls == ["Bearer stale", "Bearer fresh"]


class _Notes:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def phase(self, message: str) -> None:
        self.lines.append(message)


def test_prime_skips_unauth_and_warns_when_no_refresh() -> None:
    roles = [
        Role(name="alice", headers={"Authorization": "Bearer stale"}),  # no refresh spec
        Role(name="unauthenticated"),  # no credentials at all
    ]
    notes = _Notes()
    sm = SessionManager(roles, "http://x/graphql", reporter=notes)
    transport = _FakeTransport()
    sm.prime(transport)
    # Unauth role is never probed (nothing to validate); alice is probed once and,
    # lacking a refresh source, is left untouched but flagged for the user.
    assert transport.calls == ["Bearer stale"]
    assert sm.creds("alice").headers["Authorization"] == "Bearer stale"
    assert any("no refresh is configured" in line for line in notes.lines)


def test_refresh_stops_after_consecutive_non_productive_refreshes() -> None:
    # Refresh always yields a token the server still rejects ("stale" != "fresh"), so
    # every replay stays expired — the budget must stop us hammering the source.
    role = Role(
        name="alice",
        headers={"Authorization": "Bearer stale"},
        refresh=RefreshSpec(command="printf stale"),
    )
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    for _ in range(5):
        assert sm.graphql(transport, "alice", "{ me { email } }") is _EXPIRED
    # The first _MAX_CONSECUTIVE_REFRESH calls refresh (2 sends each: probe + replay);
    # once exhausted, the remaining 2 calls send once and never refresh again.
    assert len(transport.calls) == 2 * _MAX_CONSECUTIVE_REFRESH + 2
    assert sm.refresh("alice") is False  # exhausted: refused without re-running source


def test_refresh_budget_resets_after_a_productive_refresh(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # A source that hands out a still-rejected token first, then a good one.
    counter = tmp_path / "n"
    script = tmp_path / "refresh.sh"
    script.write_text(
        f'n=$(cat "{counter}" 2>/dev/null || echo 0)\n'
        "n=$((n+1))\n"
        f'echo "$n" > "{counter}"\n'
        'if [ "$n" -le 1 ]; then printf nope; else printf fresh; fi\n'
    )
    role = Role(
        name="alice",
        headers={"Authorization": "Bearer stale"},
        refresh=RefreshSpec(command=f"sh {script}"),
    )
    sm = SessionManager([role], "http://x/graphql")
    transport = _FakeTransport()
    # First call refreshes to a still-rejected token (non-productive, budget spent=1)...
    assert sm.graphql(transport, "alice", "{ me { email } }") is _EXPIRED
    # ...the second refreshes again (uncapped) to a good token and recovers.
    ex = sm.graphql(transport, "alice", "{ me { email } }")
    assert ex.graphql_data() == {"me": {"email": "a@b.c"}}
    assert sm.creds("alice").headers["Authorization"] == "Bearer fresh"


# --- config validation ------------------------------------------------------


def _roles_file(tmp_path, spec):  # type: ignore[no-untyped-def]
    p = tmp_path / "roles.json"
    p.write_text(json.dumps({"alice": {"headers": {"Authorization": "x"}, "refresh": spec}}))
    return p


def test_refresh_config_parsed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    spec = {
        "script": "t.py",
        "dependencies": ["requests"],
        "inject": {"template": "Bearer {token}"},
    }
    roles = load_roles(_roles_file(tmp_path, spec))
    alice = next(r for r in roles if r.name == "alice")
    assert alice.refresh is not None
    assert alice.refresh.script == "t.py"
    assert alice.refresh.dependencies == ("requests",)


def test_refresh_requires_exactly_one_source(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError):
        load_roles(_roles_file(tmp_path, {"script": "a", "command": "b"}))
    with pytest.raises(ConfigError):
        load_roles(_roles_file(tmp_path, {"dependencies": ["requests"]}))  # no source


def test_refresh_rejects_unknown_keys(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConfigError):
        load_roles(_roles_file(tmp_path, {"script": "a", "bogus": 1}))
