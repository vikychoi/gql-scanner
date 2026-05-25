# gql-scanner

A **deterministic, black-box GraphQL security scanner**. It audits a running
GraphQL endpoint against the controls in the
[OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
and emits two CSVs:

- **findings** — one row per issue: `check_id, issue_name, severity, confidence,
  operation, description, remediation, evidence, signals`. It names the affected
  query/mutation rather than embedding raw HTTP; the full verbatim request/response
  for each finding lives in the optional `--json-out` JSONL report (for replay).
- **access matrix** — which query/mutation each role (including `unauthenticated`)
  can reach.

Same target + same inputs + same version ⇒ byte-identical output (see
[determinism](#determinism)).

## Install / run

Managed with [`uv`](https://docs.astral.sh/uv/). Run without installing via `uvx`:

```bash
# from a published index
uvx gql-scanner scan --url https://target/graphql --roles roles.json

# from local source
uvx --from . gql-scanner scan --url https://target/graphql --roles roles.json

# local dev
uv run gql-scanner scan --url https://target/graphql --roles roles.json
```

## Usage

```bash
gql-scanner scan \
  --url https://target/graphql \
  [--roles roles.json] \
  [--schema schema.graphql|introspection.json] \
  [--findings-out gql-scanner-findings.csv] \
  [--matrix-out gql-scanner-access-matrix.csv] \
  [--checks ID,ID] [--skip ID,ID] \
  [--skip-mutations] \
  [--timeout 15] [--max-depth 15] [--rps 5.0] \
  [--proxy http://127.0.0.1:8080] [--insecure|-k] \
  [--json-out report.jsonl] \
  [--fail-on none|low|medium|high|critical] \
  [--min-confidence 0.0] [--verbose|-v]
```

Exit codes: `0` completed (no findings ≥ `--fail-on`), `1` findings at threshold,
`2` usage/config error, `3` target unreachable.

- **Mutations are tested by default** (so the access matrix and BFLA/auth checks
  cover state-changing operations). Pass `--skip-mutations` for a strictly
  read-only scan.
- **`--proxy URL`** routes all traffic through an intercepting proxy (Burp/ZAP).
- **`--insecure` / `-k`** skips TLS verification on `https` targets (lab use).
- **`-v` / `--verbose`** streams live progress — the current check, each probe
  being sent (e.g. `testing SQL injection at pastes.filter`), and findings as
  they are discovered. Progress is on stderr; output files are unaffected.

### Roles file (`--roles`)

Optional. Maps each role to its credentials. A synthetic `unauthenticated` role is
always tested in addition to those declared; if `--roles` is omitted, the scan runs
as `unauthenticated` only.

```json
{
  "admin":  { "headers": { "Authorization": "Bearer eyJ..." }, "privilege": 10 },
  "alice":  { "headers": { "Authorization": "Bearer eyJ..." },
              "owns": { "paste": ["1", "2"] }, "privilege": 1 },
  "bob":    { "cookies": { "session": "def456" },
              "owns": { "paste": ["3"] }, "privilege": 1 }
}
```

Optional per-role keys for ground-truth authorization testing:

- `owns` — `{ object_field: [ids] }` the role legitimately owns; BOLA verifies
  *other* roles cannot read them (high-confidence finding when they can).
- `privilege` — integer (higher = more access); BFLA flags privilege inversion
  (a lower-privilege role allowed where a higher one is denied).

### Schema file (`--schema`)

Required only when introspection is disabled. Accepts either an introspection JSON
document (`{"data": {"__schema": ...}}`) or SDL (`.graphql`). If both introspection
and `--schema` are available, the supplied file wins.

## Checks

| Area | check IDs |
|---|---|
| Configuration | `GQL-INTROSPECTION-ENABLED`, `GQL-GRAPHIQL-EXPOSED`, `GQL-EXCESSIVE-ERRORS`, `GQL-FIELD-SUGGESTIONS`, `GQL-SCHEMA-RECONSTRUCTED` |
| Authorization | `GQL-NODE-FIELD-ACCESS`, `GQL-BOLA-IDOR`, `GQL-BFLA`, `GQL-UNAUTH-ACCESS`, `GQL-EDGE-NODE-AUTHZ` |
| Denial of Service | `GQL-DEPTH-LIMIT`, `GQL-AMOUNT-LIMIT`, `GQL-PAGINATION`, `GQL-QUERY-COST`, `GQL-DIRECTIVE-OVERLOAD`, `GQL-TIMEOUT` |
| Batching | `GQL-ARRAY-BATCHING`, `GQL-ALIAS-BATCHING`, `GQL-BATCH-RATE-LIMIT`, `GQL-AUTH-BATCH` |
| Transport | `GQL-CSRF-GET`, `GQL-CORS` |
| Injection | `GQL-INJECTION-SQL`, `GQL-INJECTION-NOSQL`, `GQL-INJECTION-OS`, `GQL-INJECTION-SSRF`, `GQL-INJECTION-TEMPLATE`, `GQL-INPUT-ALLOWLIST` |

## Detection approach

Detection is **differential and confidence-scored**, not single-marker:

- **Injection** sends a benign baseline, then probes that change one variable, and
  scores the divergence — boolean-based SQLi (`OR 1=1` vs `AND 1=2` result-count
  delta), NoSQL operator interpretation, OS command injection via an inert-separator
  canary that proves *execution* (not reflection), SSRF, and template/SSTI
  (`{{7*7}}`→49). Every injectable argument is probed, including String/ID leaves
  inside input objects (via GraphQL variables).
- **Authorization** uses optional ground truth: declare each role's owned object
  IDs (`owns`) and the BOLA check verifies another role cannot read them; declare
  `privilege` levels and the BFLA check flags privilege inversion. Without ground
  truth it falls back to unauthenticated-baseline heuristics (lower confidence).
- **DoS** statically models worst-case query cost and detects type cycles from the
  schema — flagging would-be-costly queries without sending abusive requests.
- **Schema reconstruction**: when introspection is disabled and no `--schema` is
  given, the attack surface is recovered from `Cannot query field` / `Did you mean`
  validation-error oracles, then the full schema-dependent suite runs.

Each finding carries a `confidence` in [0,1] (noisy-OR of corroborating signals)
and a `signals` summary. Use `--min-confidence` to triage.

## Safety

This is an **assessment** tool. Mutation probes are sent by default so coverage
includes state-changing operations; pass `--skip-mutations` for a strictly
read-only scan against sensitive targets. Injection/DoS/batching probes use fixed,
benign canaries and hard-capped magnitudes — they detect the *absence of controls*
rather than exploiting them. Traffic only goes to the host(s) you supply.

## Determinism

Probe values, ordering, and CSV row sorting are fixed. The only time-varying output
is an optional metadata line in the `--json-out` JSONL report; the CSVs never carry
timestamps. `tests/test_determinism.py` runs a full scan twice and asserts the CSVs
are byte-identical.

## Development

```bash
uv sync
uv run ruff check src tests && uv run mypy src && uv run pytest
uv build && uvx --from dist/*.whl gql-scanner --help
```

The test suite is hermetic: it runs against in-process mock GraphQL servers
(`tests/mock_server/`) with each control toggled ON (`vulnerable`) and correctly
applied (`hardened`). Every check asserts it fires on the vulnerable server and not
on the hardened one.
