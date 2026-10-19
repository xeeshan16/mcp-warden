# Progress log

## Day 1 — 2026-10-11: scaffold and policy engine

**Done**

- Project scaffold: `src/` layout, uv + hatchling packaging, ruff (lint and format),
  strict mypy, pytest with coverage, MIT license.
- Policy-as-code model (`mcp_warden.policy.model`): versioned YAML document, rules target
  agents / servers / tools by glob; strict validation rejects unknown keys, duplicate ids,
  empty or blank patterns and unsupported versions.
- Policy engine: order-independent deny-overrides resolution
  (`deny` > `require_approval` > `allow`, then `default`), reports the deciding rule and
  every matched rule, plus `visible_tools()` for filtering `tools/list` later.
- Loader with readable error messages, a 1 MB size cap and `yaml.safe_load` only.
- HTTP app: `GET /healthz`, `GET /v1/policy`, `POST /v1/policy/evaluate` (dry run).
- CLI: `mcp-warden check <policy> [--agent --server --tool]` and `mcp-warden serve`.
- CI: Python 3.12 and 3.13 matrix running ruff, mypy, pytest, example policy validation
  and `uv build`.
- docs/PLAN.md with the 14 milestones.

**Tests:** 38 passing locally, 94% line coverage; ruff, ruff format and mypy clean;
package builds. Verified manually: `mcp-warden check` dry run and the HTTP endpoints via
`curl` against a running server.

**Next (day 2):** typed JSON-RPC 2.0 and MCP message layer (`initialize`, `tools/list`,
`tools/call`, notifications, batches) with error codes and size limits.

## Day 2 — 2026-10-12: JSON-RPC 2.0 and MCP message layer

**Done**

- `mcp_warden.jsonrpc.messages`: strict, frozen Pydantic envelopes for requests,
  notifications, success and error responses. Ids are strings or integers only (booleans,
  floats and `null` rejected for requests); unknown envelope members are rejected because
  the gateway re-serialises what it forwards.
- `mcp_warden.jsonrpc.errors`: standard JSON-RPC codes plus warden codes in the
  server-error range (policy denied, approval required, rate limited, budget exhausted,
  upstream error/timeout, payload too large, unauthenticated).
- `mcp_warden.jsonrpc.parser`: byte cap checked before decoding, strict UTF-8, duplicate
  keys and `NaN`/`Infinity` rejected, iterative nesting-depth check (and pathological
  nesting mapped to a parse error instead of a crash), batch handling with per-entry errors,
  empty-batch and batch-size checks, and a switch to refuse batches.
- `mcp_warden.jsonrpc.mcp`: typed views for `initialize`, `tools/list` and `tools/call`
  params and results. These allow unknown fields so newer MCP fields are forwarded intact,
  while the fields the gateway relies on (tool name, arguments object) are validated.
  Protocol-version negotiation and `batching_allowed()` (MCP removed batching in
  2025-06-18).
- Parser limits configurable via `WARDEN_MAX_MESSAGE_BYTES`, `WARDEN_MAX_JSON_DEPTH`,
  `WARDEN_MAX_BATCH_SIZE`.
- `.gitignore` now excludes local assistant/agent config files.

**Tests:** 103 passing locally (65 new), 97% line coverage; ruff, ruff format and strict
mypy clean.

**Next (day 3):** proxy core: Streamable HTTP endpoint `/mcp/{server}` forwarding to
upstreams via httpx, upstream registry from config, a deterministic fake MCP server for
tests, timeouts and upstream error mapping.

## Day 3 — 2026-10-13: proxy core

**Done**

- `mcp_warden.upstreams`: YAML upstream registry (`examples/upstreams.yaml`), strict
  validation (http/https URLs, unique names, timeouts, no extra keys), and upstream
  credentials via `headers_from_env`, resolved at startup so a missing variable stops
  the gateway. Gateway-owned headers (session, protocol version, framing) cannot be
  configured, and resolved credentials never appear in `repr`.
- `mcp_warden.proxy.client`: Streamable HTTP upstream client on a shared
  `httpx.AsyncClient`. Handles `application/json` and `text/event-stream` replies (own
  incremental SSE decoder), returns the response whose id matches, enforces a
  whole-reply deadline and a response size cap, and maps connect errors, HTTP errors,
  timeouts and malformed or mismatched replies to `-32005` / `-32006`. Upstream parse
  failures are relabelled so the agent never sees a `PARSE_ERROR` for the server's bytes.
- `mcp_warden.proxy.service` and `POST /mcp/{server}`: unknown servers refused before
  any network call, capped body read, hardened parsing, batches only for pre-2025-06-18
  revisions and forwarded entry by entry, `tools/call` params validated before
  forwarding, notifications acknowledged with `202`, upstream session 404s passed
  through, `Mcp-Session-Id` relayed back. Only the session and protocol-version headers
  cross from agent to upstream. `GET`/`DELETE` answer `405`.
- `mcp_warden.fake_upstream` and `mcp-warden fake-upstream [--sse]`: deterministic fake
  MCP server with sessions and read, write, destructive and slow tools.
- `mcp-warden serve --upstreams`.

**Tests:** 179 passing locally (76 new), 97% line coverage; ruff, ruff format and strict
mypy clean. The end-to-end tests run agent → gateway → fake upstream in-process for both
JSON and SSE upstreams. Also verified by hand with both servers running under uvicorn
(output in the README), including the upstream-down case.

**Next (day 4):** policy enforcement in the proxy: check `tools/call` against the policy,
filter `tools/list` responses, add argument constraints to rules, and return denials as
JSON-RPC errors. Agent identity is a placeholder header until day 5.

## Day 4 — 2026-10-14: policy enforcement in the proxy

**Done**

- Argument matchers on rules (`mcp_warden.policy.model.ArgumentMatcher`): dotted paths
  into the `tools/call` arguments (numeric segments index lists) with `equals`,
  `one_of`, `glob`, `regex` (full match), `present`, `max_length` and `min`/`max`, plus
  `not` to negate. JSON-typed equality (`1` never equals `true`), a missing value never
  satisfies anything but `present: false`, one operator per matcher (only `min`+`max`
  combine), and bad regexes or inverted ranges fail at load time.
- `PolicyEngine.always_denied()`: listing-time visibility that treats conditional rules
  as "might match", so a conditional deny never hides a tool and a conditional allow
  keeps one visible.
- `mcp_warden.proxy.enforcement.PolicyGuard`: `tools/call` is evaluated before
  forwarding; `deny` → `-32001` and `require_approval` → `-32002`, both carrying server,
  tool, effect, rule id and reason, and neither reaches the upstream. `tools/list`
  results are filtered with every other member preserved; an unreadable result fails
  closed with `-32005`. Batch entries are checked independently.
- Placeholder agent identity from `X-Warden-Agent` (missing → `anonymous`, malformed →
  `400`), replaced by API keys tomorrow.
- Dry runs take arguments: `mcp-warden check --arguments '{...}'` and an `arguments`
  field on `POST /v1/policy/evaluate`.
- Example policy: protected default branch, demo-server rules, bounded `sleep`, and a
  support-bot rule with a title-length limit.

**Tests:** 270 passing locally (91 new), 97% line coverage; ruff, ruff format, strict
mypy and `uv build` clean. New end-to-end tests run the example policy against the fake
upstream over JSON and SSE. Also verified by hand with both servers under uvicorn (output
in the README): the two denied calls never reached the fake upstream.

**Next (day 5):** agent identity: per-agent API keys (prefix + SHA-256 hash at rest,
constant-time compare), SQLAlchemy models, Alembic migrations, key issue/revoke service,
replacing the `X-Warden-Agent` placeholder.

## Day 5 — 2026-10-15: agent identity

**Done**

- `mcp_warden.db`: SQLAlchemy 2 models for `agents` and `api_keys` with a fixed
  constraint naming convention, timezone-aware UTC timestamps stored as naive UTC (same
  behaviour on SQLite and PostgreSQL), SQLite foreign keys switched on so
  `ON DELETE CASCADE` works, and an engine factory (in-memory SQLite shares one
  connection; other databases get `pool_pre_ping`).
- Alembic migrations shipped inside the package (revision `0001`), applied with
  `mcp-warden db upgrade` and no `alembic.ini` needed at runtime. The gateway refuses to
  start unless the schema is at the head revision. `alembic.ini` in the repo is only for
  authoring new revisions. A test diffs the migrated schema against the models.
- `mcp_warden.identity.keys`: `mcpw_<12 hex prefix>_<32-byte secret>` keys, SHA-256 of
  the full key at rest, `hmac.compare_digest`, a dummy comparison for unknown prefixes,
  and reprs that never include the plaintext.
- `mcp_warden.identity.store.IdentityStore`: create/list/disable agents, issue keys
  (label, optional expiry), list and revoke keys (revoking twice keeps the first
  timestamp), and `authenticate()`, which returns `None` for every failure (malformed,
  unknown, wrong secret, revoked, expired, agent disabled). `last_used_at` is written at
  most once a minute per key. Injected clock for tests.
- `mcp_warden.identity.auth`: `ApiKeyAuthenticator` (Bearer token, store call in a worker
  thread) and `TrustedHeaderAuthenticator` (the old `X-Warden-Agent` behaviour, now opt-in
  via `WARDEN_AUTH_MODE=trusted-header`). Failures are `401` with JSON-RPC `-32008` and
  `WWW-Authenticate: Bearer realm="mcp-warden"`.
- The proxy authenticates before resolving the server, so unauthenticated callers cannot
  probe which upstreams exist; the agent's key is never forwarded upstream.
- CLI: `mcp-warden db upgrade`, `agents create|list|disable|enable`,
  `keys issue|list|revoke` (the key is printed once on stdout, details on stderr).
- New settings `WARDEN_DATABASE_URL` and `WARDEN_AUTH_MODE`; `psycopg[binary]` available
  as the `postgres` extra.

**Tests:** 334 passing locally (64 new), 98% line coverage; ruff, ruff format, strict
mypy and `uv build` clean, and the wheel contains the migration scripts. New end-to-end
tests run the gateway in API key mode against the fake upstream: missing and invalid
keys, identity taken from the key (a spoofed `X-Warden-Agent` is ignored), immediate
revocation, and no `Authorization` header on the upstream leg. Also verified by hand
with both servers under uvicorn and a fresh SQLite file (output in the README).

**Next (day 6):** rate limiting: token buckets per agent and per agent+tool with an
injected clock, in-memory and database-backed stores, `-32003` errors with retry
information.

## Day 6 — 2026-10-16: rate limiting

**Done**

- `rate_limits` section in the policy (`mcp_warden.policy.model.RateLimit`): agent /
  server / tool globs, `requests` per `second|minute|hour|day`, optional `burst` (bucket
  size, defaults to `requests`), and `scope: agent` (one bucket per agent) or
  `scope: tool` (per agent, server and tool). Strict validation (integers only, no
  booleans, unknown keys rejected, unique ids). `PolicyEngine.rate_limits_for()`
  returns the limits that apply to a call.
- `mcp_warden.ratelimit.bucket`: storage-free token-bucket arithmetic. Levels are derived
  from the last recorded level and time (no timers), a clock going backwards adds
  nothing, and acquisition is all-or-nothing across a call's buckets with the longest
  wait reported as `retry_after`.
- `InMemoryBucketStore`: injected monotonic clock, a lock, and bounded memory (refilled
  buckets swept, then least recently used evicted past 100,000).
- `DatabaseBucketStore` and Alembic revision `0002` (`rate_limit_buckets`): one short
  transaction per call, `SELECT ... FOR UPDATE` in digest order, writes only when
  allowed, SHA-256 keys, one retry when a concurrent caller inserts the same row first,
  `full_at` index and `prune()` for refilled buckets. Wall-clock epoch seconds so
  several hosts agree.
- `RateLimiter` in the proxy: checked after the policy (denied calls spend nothing),
  `-32003` with the limit's details and `retry_after` in whole seconds, plus a
  `Retry-After` header on single (non-batch) responses that only the gateway's own
  refusals set. Batch entries take tokens independently.
- `WARDEN_RATE_LIMIT_STORE=memory|database`; the database store works in either auth
  mode and the gateway refuses to start if the schema is behind.
- `mcp-warden check` and `GET /v1/policy` show rate limits; the example policy has three.
- CI: a PostgreSQL 16 service and `WARDEN_TEST_POSTGRES_URL`, so the database store
  tests also run against PostgreSQL (brought forward from day 13).

**Tests:** 388 passing locally on SQLite (54 new) with 10 PostgreSQL variants skipped;
398 passing with a local PostgreSQL 16, 98% line coverage. ruff, ruff format, strict
mypy and `uv build` clean. The PostgreSQL concurrency test (8 threads, 4 store
instances, one 10-token bucket, exactly 10 calls pass) was checked to fail with the row
lock removed (57 passed instead of 10). Verified by hand with both servers under uvicorn
and the database store on PostgreSQL (output in the README): the fourth ticket in a
minute got `-32003` and `Retry-After: 20` and never reached the fake upstream.

**Next (day 7):** budgets: call and token budgets per agent per window, a
`TokenEstimator` interface with a deterministic estimator, a usage ledger, and
`-32004` budget-exhausted errors.

## Day 7 — 2026-10-17: budgets

**Done**

- `budgets` section in the policy (`mcp_warden.policy.model.Budget`): agent / server /
  tool globs, `window: hour|day|week|month` (fixed UTC windows, weeks from Monday),
  `max_calls` and/or `max_tokens` (at least one), `scope: agent|tool`. Strict
  validation as for rate limits; `PolicyEngine.budgets_for()`.
- `mcp_warden.budget`:
  - `TokenEstimator` protocol and the deterministic `CharRatioEstimator`
    (`ceil(chars / 4)`, configurable with `WARDEN_CHARS_PER_TOKEN`) over canonical JSON,
    so key order and whitespace never change a count;
  - `window_bounds()` for the four windows (year rollover, other time zones converted);
  - the pure ledger logic: charges keyed by budget id and subject, all-or-nothing
    `decide()` that reports the exhausted budget resetting last;
  - `InMemoryUsageStore` (bounded: ended windows swept first, then LRU) and
    `DatabaseUsageStore` (row-locked reserve in a fixed order, one retry on a
    concurrent insert, atomic `tokens = tokens + n` settle, `records()` and `prune()`);
  - `BudgetEnforcer`: reserve before forwarding, settle the reply's tokens after, and
    `-32004` errors with `exhausted`, `used`, `limit`, `resets_at` and `retry_after`.
- Alembic revision `0003` (`usage_counters`): one row per counter and window with
  readable labels (cut to 200 characters; the digest identifies the counter).
- Proxy: budgets run after the policy and rate limits; a forwarded call counts even if
  the upstream fails; a failure to record reply tokens is logged and never fails the
  call. `RetryAfterError` is now the shared base for rate-limit and budget refusals,
  so both set `Retry-After` on single requests.
- `WARDEN_USAGE_STORE=memory|database`; `mcp-warden usage [--agent] [--all]` reports the
  database ledger; `mcp-warden check` and `GET /v1/policy` show budgets; the example
  policy has three budgets.

**Tests:** 454 passing locally on SQLite (66 new) with 21 PostgreSQL variants skipped;
474 passing with a local PostgreSQL 16 (only the SQLite variant of the concurrency
test skipped), 99% line coverage. ruff, ruff format, strict
mypy and `uv build` clean. The PostgreSQL concurrency test (8 threads, 4 store
instances, one budget of 10 calls, exactly 10 booked) was checked to fail with the row
lock removed (48 booked). Verified by hand with both servers under uvicorn and both
stores on PostgreSQL (output in the README): the 51st echo in an hour got `-32004` and
`Retry-After: 3482` and never reached the fake upstream, while `add` still passed.

**Next (day 8):** human approval: park `require_approval` calls in an approvals table,
an admin approve/deny API, the agent receives a pending status or the result after
approval, and expiry.

## Day 8 — 2026-10-18: human approval

**Done**

- `mcp_warden.approval`:
  - approval requests identified by a fingerprint (SHA-256 of agent, server, tool and
    canonical arguments), with `pending → approved → executed`, `pending → denied` and
    lazy expiry; arguments kept for the reviewer and dropped once a request is denied,
    executed or expired (digest and size remain);
  - `InMemoryApprovalStore` (bounded, finished requests evicted first) and
    `DatabaseApprovalStore`: a unique `open_key` stops identical calls from opening two
    requests (the losing insert retries once), and claim/decide are single conditional
    `UPDATE`s, so an approval is spent exactly once;
  - `ApprovalGate`: pending → `-32002` with `approval_id`, `expires_at` and
    `Retry-After`; approved → admitted and claimed just before forwarding; denied →
    `-32001` with reviewer and note while the decision holds; a per-agent cap on
    waiting requests (`-32003`); an optional in-gateway wait that polls for a decision.
- Alembic revision `0004` (`approval_requests`).
- Proxy: `require_approval` goes to the gate after the rules and before rate limits and
  budgets; the approval is spent last so a rate-limited call keeps it.
  `PolicyGuard.evaluate_call` separates the deny check from approval routing.
- Admin API behind `WARDEN_ADMIN_TOKEN` (bearer, constant-time compare, disabled with
  `503` when unset): list, show, approve and deny under `/v1/approvals`; `409` for
  requests that are no longer pending.
- CLI: `mcp-warden approvals list|show|approve|deny` on the database store.
- Settings: `WARDEN_APPROVAL_STORE`, `..._TTL_SECONDS`, `..._DECISION_TTL_SECONDS`,
  `..._WAIT_SECONDS`, `..._MAX_PENDING_PER_AGENT`, `..._RETRY_AFTER_SECONDS`,
  `WARDEN_ADMIN_TOKEN`.
- Example policy: `urgent-tickets-need-a-human` for the support bot's urgent demo tickets.

**Tests:** 517 passing locally on SQLite (83 new) with 41 PostgreSQL variants skipped;
557 passing with a local PostgreSQL 16, 99% line coverage. ruff, ruff format, strict
mypy and `uv build` clean, and the wheel contains migration `0004`. The PostgreSQL
tests race 8 threads opening the same request (one request results) and 8 threads
claiming one approval (exactly one wins). Without the retry on the unique key, the open
race raised 26 integrity errors in 5 rounds of 8 threads. Verified by hand with both
servers under uvicorn, API keys and the database store on PostgreSQL (output in the
README): the urgent ticket was parked, approved over the admin API, ran once, the
repeat opened a new request, which was denied from the CLI; the fake upstream saw only
`initialize` and the one approved call.

**Next (day 9):** audit log: metadata-only records (agent, server, tool, decision,
latency, argument hash and size, never payloads), query API with filters and cursor
pagination, and a retention job (which also prunes ended budget windows, refilled
rate-limit buckets and finished approval requests).

## Day 9 — 2026-10-19: audit log and retention

**Done**

- `mcp_warden.audit`:
  - `AuditEvent`: time, agent, server, method, tool, outcome (`forwarded`, `denied`,
    `approval_pending`, `rate_limited`, `budget_exhausted`, `upstream_error`,
    `invalid`, `error`), policy effect, rule id, approval id, JSON-RPC error code,
    the tool result's `isError`, latency, and the arguments' digest and byte size.
    Never arguments, results or error messages;
  - `ArgumentHasher`: SHA-256 of canonical JSON, or HMAC-SHA-256 with
    `WARDEN_AUDIT_HASH_KEY` (16+ bytes), so small argument objects cannot be recovered
    by hashing guesses;
  - `InMemoryAuditStore` (bounded ring) and `DatabaseAuditStore` (append-only
    `audit_events`), both with filters (agent, server, tool, method, outcome,
    since/until) and keyset pagination on `(occurred_at, id)` with opaque cursors;
  - `AuditRecorder`: builds events from what the proxy learned about each request and
    writes them in a worker thread; fail-open, with failures logged and counted.
- Alembic revision `0005` (`audit_events`, composite `(occurred_at, id)` index).
- Proxy: one event per JSON-RPC request routed to an upstream, including refusals and
  a lost upstream session; the events of one HTTP request (a batch included) are
  written in one transaction once every entry is answered.
- `GET /v1/audit` behind the admin token; `mcp-warden audit` with the same filters,
  `--cursor` paging and `--json`.
- `mcp_warden.retention.RetentionJob`: prunes audit events, finished approval requests
  (new `prune()` on both approval stores), ended budget windows and refilled rate-limit
  buckets. Runs as `mcp-warden retention [--days N]` or inside the gateway every
  `WARDEN_RETENTION_INTERVAL_SECONDS`; a failed run is logged and retried.
- Settings: `WARDEN_AUDIT_STORE=memory|database|off`, `WARDEN_AUDIT_HASH_KEY`,
  `WARDEN_AUDIT_MEMORY_MAX_EVENTS`, `WARDEN_RETENTION_DAYS`,
  `WARDEN_RETENTION_INTERVAL_SECONDS`.

**Tests:** 584 passing locally on SQLite (67 new) with 51 PostgreSQL variants skipped;
634 passing with a local PostgreSQL 16, 99% line coverage (100% for the new modules).
ruff, ruff format and strict mypy clean. New tests cover both stores against one
contract (filters, newest-first order, paging with equal timestamps, writes during
paging, pruning), the proxy end to end (every outcome, batches written once, a failing
store not failing the call, no argument or result text anywhere in the events), the
query API and CLI, and the retention job on SQLite and PostgreSQL. Verified by hand with
both servers under uvicorn, API keys and the database stores on PostgreSQL (output in
the README): a ticket title containing "4711" appears in no `audit_events` row.

**Next (day 10):** admin API and CLI: manage agents, keys and policies (validated hot
reload) over HTTP, approvals and usage views, admin authentication, CLI parity.
