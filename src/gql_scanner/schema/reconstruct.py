"""Reconstruct a schema when introspection is disabled (Clairvoyance-style).

GraphQL servers leak their schema through *validation errors* even with
introspection off:

* ``Cannot query field "X" on type "Query".`` — so ``X`` is **not** a field; a
  probe that does *not* produce this error means ``X`` **is** a real field.
* ``Did you mean "a", "b"?`` — suggestions name real nearby fields, harvested to
  expand the candidate set beyond the static wordlist.
* ``Field "f" of type "T" must have a selection of subfields`` — ``f`` returns an
  object; ``... must not have a selection`` / a resolved value — a scalar.

We test a fixed wordlist (plus harvested suggestions) for membership against the
Query and Mutation roots, classify each hit, and synthesize a minimal SDL the
rest of the scanner can consume. Bounded request budget; deterministic order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from graphql import GraphQLSchema, build_schema

from ..exchange import Exchange
from ..transport import Transport

# Common GraphQL root field names. Deterministic, fixed order.
WORDLIST: tuple[str, ...] = (
    "me",
    "viewer",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "node",
    "nodes",
    "search",
    "query",
    "feed",
    "post",
    "posts",
    "paste",
    "pastes",
    "comment",
    "comments",
    "article",
    "articles",
    "product",
    "products",
    "order",
    "orders",
    "item",
    "items",
    "customer",
    "customers",
    "employee",
    "admin",
    "role",
    "roles",
    "permission",
    "permissions",
    "token",
    "tokens",
    "session",
    "settings",
    "config",
    "system",
    "systemHealth",
    "systemDebug",
    "systemUpdate",
    "systemDiagnostics",
    "audits",
    "audit",
    "logs",
    "log",
    "file",
    "files",
    "upload",
    "download",
    "image",
    "images",
    "message",
    "messages",
    "notification",
    "notifications",
    "group",
    "groups",
    "team",
    "teams",
    "organization",
    "project",
    "projects",
    "task",
    "tasks",
    "event",
    "events",
    "invoice",
    "payment",
    "transaction",
    "report",
    "reports",
    "secret",
    "secrets",
    "key",
    "apiKey",
    "readAndBurn",
    "deleteAllPastes",
    "health",
    "status",
    "version",
    "ping",
    # common mutations
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "createUser",
    "updateUser",
    "deleteUser",
    "createPost",
    "editPost",
    "deletePost",
    "createPaste",
    "editPaste",
    "deletePaste",
    "uploadPaste",
    "importPaste",
    "resetPassword",
    "changePassword",
    "createOrder",
    "updateProfile",
    "promoteUser",
    "addUser",
    "removeUser",
)

_CANNOT_QUERY = re.compile(r'cannot query field "?([\w]+)"?', re.IGNORECASE)
_DID_YOU_MEAN = re.compile(r"did you mean ([^?.]+)", re.IGNORECASE)
_QUOTED = re.compile(r'["\']([\w]+)["\']')
_NEEDS_SELECTION = re.compile(r"must have a selection of subfields", re.IGNORECASE)
_NO_SELECTION = re.compile(r"must not have a selection", re.IGNORECASE)

# Bound the work so reconstruction stays fast and deterministic.
_MAX_PROBES = 400


@dataclass
class ReconstructResult:
    query_fields: dict[str, str] = field(default_factory=dict)  # name -> "scalar"|"object"
    mutation_fields: dict[str, str] = field(default_factory=dict)
    probes: int = 0

    @property
    def found(self) -> bool:
        return bool(self.query_fields or self.mutation_fields)

    def summary(self) -> str:
        q = ", ".join(sorted(self.query_fields))
        m = ", ".join(sorted(self.mutation_fields))
        parts = []
        if q:
            parts.append(f"queries: {q}")
        if m:
            parts.append(f"mutations: {m}")
        return "; ".join(parts)


def _error_messages(ex: Exchange) -> list[str]:
    return [e.get("message", "") for e in ex.graphql_errors() if isinstance(e.get("message"), str)]


def _classify(messages: list[str], candidate: str) -> str | None:
    """Return "scalar"/"object" if candidate is a valid field, else None."""
    joined = " ".join(messages).lower()
    if not messages:
        return "scalar"  # resolved cleanly => leaf returned a value
    # If the server says this exact field cannot be queried, it is not a field.
    for m in messages:
        cq = _CANNOT_QUERY.search(m)
        if cq and cq.group(1) == candidate:
            return None
    if _NEEDS_SELECTION.search(joined):
        return "object"
    # Any other error (required arg, no-selection, type) implies the field exists.
    return "scalar"


def _harvest(messages: list[str]) -> set[str]:
    out: set[str] = set()
    for m in messages:
        dym = _DID_YOU_MEAN.search(m)
        if dym:
            out.update(_QUOTED.findall(dym.group(1)))
    return out


def _probe_root(
    transport: Transport,
    url: str,
    op_type: str,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | None,
    budget: list[int],
) -> dict[str, str]:
    """Enumerate fields of one root (query/mutation) by wordlist membership."""
    found: dict[str, str] = {}
    queue: list[str] = list(WORDLIST)
    seen: set[str] = set()
    while queue and budget[0] < _MAX_PROBES:
        candidate = queue.pop(0)
        if candidate in seen:
            continue
        seen.add(candidate)
        budget[0] += 1
        ex = transport.graphql(
            url, f"{op_type} {{ {candidate} }}", headers=headers, cookies=cookies
        )
        messages = _error_messages(ex)
        for s in sorted(_harvest(messages)):
            if s not in seen:
                queue.append(s)
        kind = _classify(messages, candidate)
        if kind is not None:
            found[candidate] = kind
    return found


def _synthesize_sdl(result: ReconstructResult) -> str:
    def render(fields: dict[str, str]) -> str:
        lines = []
        for name in sorted(fields):
            # Object fields point at a shared placeholder type so a minimal probe
            # can select a subfield; scalar fields are plain String.
            lines.append(
                f"  {name}: ReconObject" if fields[name] == "object" else f"  {name}: String"
            )
        return "\n".join(lines) or "  _placeholder: String"

    sdl = f"type Query {{\n{render(result.query_fields)}\n}}\n"
    if result.mutation_fields:
        sdl += f"type Mutation {{\n{render(result.mutation_fields)}\n}}\n"
    sdl += "type ReconObject { id: ID name: String }\n"
    return sdl


def reconstruct(
    transport: Transport,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> ReconstructResult:
    """Best-effort schema reconstruction via validation-error oracles."""
    budget = [0]
    result = ReconstructResult()
    result.query_fields = _probe_root(transport, url, "query", headers, cookies, budget)
    result.mutation_fields = _probe_root(transport, url, "mutation", headers, cookies, budget)
    result.probes = budget[0]
    return result


def reconstruct_schema(result: ReconstructResult) -> GraphQLSchema | None:
    """Synthesize a parseable :class:`GraphQLSchema` from a reconstruction."""
    if not result.found:
        return None
    return build_schema(_synthesize_sdl(result))
