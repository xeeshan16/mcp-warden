# MCP Warden

[![CI](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A self-hosted policy, budget and audit gateway for AI agent tool calls over the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP).**

> Status: under active development (day 12 of a 14-day build). See
> [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/PROGRESS.md](docs/PROGRESS.md)
> for the daily log. Features marked _planned_ are not implemented yet.

## The problem

Teams are wiring AI agents to MCP servers that can read tickets, open pull requests,
query databases and send messages. Each MCP server exposes every tool it has to every
client that connects, and most agent frameworks offer little control beyond "connect"
or "don't". That leaves platform teams without answers to basic questions:

- Which agent is allowed to call which tool on which server?
- How do we stop a looping agent from making 10,000 calls overnight?
- Which actions need a human to sign off first?
- What did each agent actually do, and when, without logging sensitive payloads?

MCP Warden sits between agents and MCP servers and answers those questions centrally,
with a policy file you can review in a pull request.

## Features

| Feature | Status |
| --- | --- |
| Policy-as-code (YAML): allow / deny / require_approval by agent, server and tool glob | ✅ day 1 |
| Deny-overrides resolution that rule order can never weaken | ✅ day 1 |
| Policy validation CLI with dry-run decisions (`mcp-warden check`) | ✅ day 1 |
| Policy dry-run HTTP API (`POST /v1/policy/evaluate`) | ✅ day 1 |
| Hardened JSON-RPC 2.0 parser (size, depth and batch limits; duplicate keys rejected) | ✅ day 2 |
| Typed MCP messages (`initialize`, `tools/list`, `tools/call`) and protocol negotiation | ✅ day 2 |
| MCP proxy over Streamable HTTP (`POST /mcp/{server}`), JSON and SSE upstream replies | ✅ day 3 |
| Upstream registry; upstream credentials resolved from env vars, never sent by agents | ✅ day 3 |
| Upstream timeouts, size caps and error mapping to JSON-RPC errors | ✅ day 3 |
| Deterministic fake MCP server for tests and demos (`mcp-warden fake-upstream`) | ✅ day 3 |
| Policy enforcement on `tools/call` and `tools/list` filtering in the proxy | ✅ day 4 |
| Argument matchers on tool calls (equals, one_of, glob, regex, present, max_length, min/max) | ✅ day 4 |
| Per-agent API keys: SHA-256 at rest, constant-time compare, expiry, revocation | ✅ day 5 |
| SQLAlchemy models and Alembic migrations (SQLite for dev, PostgreSQL driver extra) | ✅ day 5 |
| `mcp-warden db` / `agents` / `keys` commands to manage identities | ✅ day 5 |
| Rate limits in the policy: token buckets per agent or per agent and tool, `Retry-After` | ✅ day 6 |
| Rate-limit state in memory or shared through the database (row-locked on PostgreSQL) | ✅ day 6 |
| Call and token budgets per hour, day, week or month, per agent or per agent and tool | ✅ day 7 |
| Usage ledger in memory or the database, `mcp-warden usage` report | ✅ day 7 |
| Human approval for `require_approval` calls: parked requests, single-use approvals, expiry | ✅ day 8 |
| Admin API (`/v1/approvals`, bearer token) and `mcp-warden approvals` to review the queue | ✅ day 8 |
| Metadata-only audit log: one event per request, argument digest and size, never payloads | ✅ day 9 |
| Audit query API (`GET /v1/audit`) and `mcp-warden audit`, with filters and cursor pagination | ✅ day 9 |
| Retention job (`mcp-warden retention` or in the gateway) for audit, approvals, usage, buckets | ✅ day 9 |
| Admin API for agents, keys and budget usage (`/v1/agents`, `/v1/keys`, `/v1/usage`) | ✅ day 10 |
| Named admin tokens; approval decisions recorded under the authenticated admin | ✅ day 10 |
| Validated policy hot reload (`POST /v1/policy/reload`, `mcp-warden policy reload`, file watch) | ✅ day 10 |
| Prometheus metrics (`GET /metrics`) with bounded labels, optional bearer token | ✅ day 11 |
| OpenTelemetry tracing: a span per request, W3C context from agent to upstream, OTLP export | ✅ day 11 |
| Structured JSON logs with trace and span ids (`WARDEN_LOG_FORMAT=json`) | ✅ day 11 |
| Container image (multi-stage uv build, non-root user, health check) | ✅ day 12 |
| Docker Compose stack: PostgreSQL, migrations, gateway and fake upstream; read-only, no capabilities | ✅ day 12 |
| Scripted end-to-end demo agent (`mcp-warden demo`), run in CI against the Compose stack | ✅ day 12 |
| PostgreSQL integration tests in CI, JSON-RPC fuzzing, threat model | _planned_ (day 13) |

## Architecture

```mermaid
flowchart LR
    A[AI agent<br/>MCP client] -- "JSON-RPC + API key" --> W
    subgraph W[MCP Warden]
        direction TB
        AU[Authenticate agent] --> P[Policy engine]
        P --> AP[Approval queue]
        AP --> RL[Rate limits and budgets]
        RL --> AL[Audit log]
    end
    W -- "forward allowed calls" --> S1[MCP server: github]
    W --> S2[MCP server: tickets]
    W -.-> DB[(PostgreSQL)]
    W -.-> M[Prometheus / OTel]
```

So far the policy engine (day 1), the JSON-RPC / MCP message layer (day 2), the proxy
path to upstream servers (day 3), policy enforcement inside the proxy (day 4), agent
authentication with API keys (day 5), rate limits (day 6), budgets (day 7), human
approval (day 8), the audit log with its retention job (day 9), the admin API with
policy hot reload (day 10) and observability (day 11) are in place. Packaging and the
Docker Compose demo land next (see the plan).

### Policy resolution

Every rule whose `agents`, `servers` and `tools` patterns all match the request is
collected. The most restrictive effect wins: `deny` > `require_approval` > `allow`.
If no rule matches, the policy `default` applies (and it defaults to `deny`).
Because the result does not depend on rule order, appending an `allow` rule can never
override an existing `deny`.

```yaml
version: 1
default: deny
rules:
  - id: read-only-everywhere
    effect: allow
    tools: ["get_*", "list_*", "search_*", "read_*"]
  - id: writes-need-a-human
    effect: require_approval
    servers: ["github"]
    tools: ["create_*", "update_*", "merge_*", "push_*"]
  - id: never-destructive
    effect: deny
    tools: ["delete_*", "drop_*", "*_delete", "purge_*"]
```

Unknown keys, duplicate rule ids, empty pattern lists and unsupported versions are
rejected at load time, so a typo fails loudly instead of silently widening access.

#### Argument matchers

A rule can also look at the `tools/call` arguments. It then applies only when every
matcher holds:

```yaml
  - id: no-pushes-to-default-branch
    effect: deny
    servers: ["github"]
    tools: ["push_*", "create_or_update_file"]
    arguments:
      - {path: branch, one_of: ["main", "master"]}

  - id: short-sleeps-only
    effect: deny
    servers: ["demo"]
    tools: ["sleep"]
    arguments:
      - {path: seconds, min: 0, max: 2, not: true}   # also denies a missing value
```

| Operator | Holds when the value at `path` … |
| --- | --- |
| `equals` / `one_of` | equals the given JSON value(s); typed, so `1` never equals `true` |
| `glob` / `regex` | is a string matching the glob, or fully matching the regex |
| `present` | resolves (`true`) or does not resolve (`false`) |
| `max_length` | is a string, list or object of at most that length |
| `min` / `max` | is a number within the inclusive bounds (may be combined) |

`path` uses dot notation (`options.mode`, `files.0`). A missing value never satisfies an
operator other than `present: false`, and `not: true` negates the result, so a negated
deny fails closed. Each matcher takes exactly one operator; invalid regexes and inverted
ranges are rejected at load time. Globs are plain string matching, not path
normalisation: to fence a file path, prefer a `regex` and a deny rule for `..`.
Regexes come from the policy author, who is trusted; keep them simple.

### Parsing untrusted JSON-RPC

Everything an agent sends passes through `mcp_warden.jsonrpc.parse_payload` before any
decision is made. It enforces a byte cap before decoding, strict UTF-8, a nesting-depth
cap and a batch-size cap, and it rejects `NaN`/`Infinity` literals and **duplicate object
keys**: if `{"name": "get_issue", "name": "delete_repo"}` were accepted, the gateway and
the upstream server could disagree about which tool is being called. Invalid entries in a
batch get their own JSON-RPC error instead of failing the whole batch.

Gateway refusals use codes from the JSON-RPC server-error range so clients can tell them
apart from upstream failures:

| Code | Meaning |
| --- | --- |
| -32001 | denied by policy |
| -32002 | human approval required (the call was parked; repeat it to collect the decision) |
| -32003 | rate limited |
| -32004 | budget exhausted |
| -32005 / -32006 | upstream error / upstream timeout |
| -32007 | payload too large |
| -32008 | unauthenticated |

MCP revisions from 2025-06-18 onward removed JSON-RPC batching, so batches are only
accepted when the client declares an older revision in `MCP-Protocol-Version`.

### Proxying to upstream servers

Agents talk to `POST /mcp/{server}`, where `server` is a name from the upstream registry
(`examples/upstreams.yaml`). For each message the gateway:

1. refuses unknown server names with a 404 before any network call;
2. parses the payload with the hardened parser above;
3. forwards requests and returns the upstream's response, whether the upstream answered
   with `application/json` or a `text/event-stream`; notifications are acknowledged
   with `202`;
4. maps failures to JSON-RPC errors that keep the request id: connection failures and
   HTTP errors become `-32005`, exceeding the upstream's deadline becomes `-32006`
   (the deadline covers the whole reply, so an SSE stream that only sends keep-alives
   still times out), and oversized, malformed or mismatched replies become `-32005`.

Only `Mcp-Session-Id` and `MCP-Protocol-Version` are passed from the agent to the
upstream. The agent's own `Authorization` header and cookies are for the gateway and are
never forwarded; upstream credentials are configured per server with `headers_from_env`,
which names an environment variable read at startup. A missing variable stops startup.
When an upstream answers `404` for a session id, the 404 is passed through so the client
starts a new session, as MCP specifies. Batch entries are forwarded one by one, so later
per-call checks apply the same way whether or not calls were batched.

### Enforcing the policy

Inside the proxy, each `tools/call` is validated and then evaluated with the agent, the
upstream name, the tool name and its arguments **before** anything is forwarded:

- `deny` → error `-32001` with the deciding rule; the upstream never sees the call;
- `require_approval` → parked for a human (see [Human approval](#human-approval));
- `allow` → forwarded.

`tools/list` replies are filtered so an agent is only shown tools it could ever call.
A tool is hidden when an unconditional `deny` applies, or when no rule could permit it
and the default is `deny`. Rules with argument matchers keep a tool visible, since the
arguments are only known at call time (the call itself is still checked). Everything
else in the result (the pagination cursor, `_meta`, each tool's schema and annotations)
is forwarded untouched, and a `tools/list` result the gateway cannot read is refused
with `-32005` instead of being passed through unfiltered. Batch entries are checked one
by one.

### Rate limits

Rate limits are declared next to the rules in the policy file, so they are reviewed the
same way:

```yaml
rate_limits:
  - id: per-agent              # every call, one bucket per agent
    requests: 120
    per: minute                # second | minute | hour | day
    burst: 30                  # bucket size; defaults to `requests`

  - id: source-control-writes
    servers: ["github"]
    tools: ["create_*", "update_*", "merge_*", "push_*"]
    scope: tool                # one bucket per agent, server and tool
    requests: 20
    per: hour
    burst: 5
```

Each limit is a token bucket: it holds up to `burst` tokens and refills continuously at
`requests / per`. A `tools/call` needs one token from **every** limit that matches it
(by agent, server and tool glob), so adding a limit can only make things stricter.

- Limits are checked **after** the policy rules: a denied call never spends a token.
- Taking tokens is all-or-nothing across a call's buckets, so a refused call drains
  nothing and tokens are never lost to a call that did not happen.
- A refused call gets JSON-RPC error `-32003` with the limit, its numbers and
  `retry_after` (whole seconds until every bucket involved has a token, rounded up).
  For a single request the gateway also sets a `Retry-After` header; the HTTP status
  stays `200` because MCP clients act on the JSON-RPC error. Only the gateway's own
  refusals set the header, never an upstream's error.
- Each entry of a (pre-2025-06-18) batch takes its own token.
- `tools/list`, `initialize` and notifications are not limited.

Where the buckets live is a deployment choice (`WARDEN_RATE_LIMIT_STORE`):

- `memory` (default): in-process, exact, per gateway instance. Memory is bounded:
  buckets that have refilled are dropped, and past 100,000 buckets the least recently
  used go first.
- `database`: one row per bucket below capacity in `rate_limit_buckets`, shared by every
  gateway using the database. Each call is one short transaction that locks its rows
  with `SELECT ... FOR UPDATE` in a fixed key order (no deadlocks), derives the current
  levels and writes only when the call is allowed. Keys are stored as SHA-256 digests;
  rows of refilled buckets can be pruned. A test runs 8 threads through 4 separate store
  instances against one PostgreSQL bucket of 10 tokens and checks that exactly 10 calls
  pass (with the row lock removed, it fails). On SQLite, calls are serialised inside the
  process, so use PostgreSQL for more than one instance.

Buckets are keyed by the limit's `id`: changing a limit's numbers keeps the current
levels (clamped to the new size), renaming it starts afresh.

### Budgets

Rate limits smooth bursts; budgets cap totals. A budget allows at most `max_calls` calls
and/or `max_tokens` estimated tokens per fixed UTC window:

```yaml
budgets:
  - id: daily-calls            # every agent, every call
    window: day                # hour | day | week (from Monday) | month
    max_calls: 2000

  - id: support-bot-tokens
    agents: ["support-bot"]
    window: day
    max_tokens: 200000         # request arguments + tool replies

  - id: demo-echo
    servers: ["demo"]
    tools: ["echo"]
    scope: tool                # one counter per agent, server and tool
    window: hour
    max_calls: 50
    max_tokens: 5000
```

- Budgets are checked **after** the rules and the rate limits, so denied and
  rate-limited calls spend no budget. Every budget that matches a call must have room.
- Booking is two-phase. Before forwarding, the call and its request tokens are reserved
  against all of its budgets at once (all or nothing; a refused call books nothing).
  When the reply arrives, its tokens are added. A reply's size is unknown in advance,
  so the call that crosses a token limit completes and every later call in that window
  is refused; refusing it would mean refusing a call whose tool already ran.
- A forwarded call counts even if the upstream then fails or times out: the tool may
  have run, and a budget that an upstream failure could refund would not be a budget.
- A refused call gets JSON-RPC error `-32004` with the budget, which limit ran out
  (`calls` or `tokens`), usage, `resets_at` and `retry_after`, plus a `Retry-After`
  header on single requests. With several exhausted budgets, the one that resets last
  is reported, because the call cannot pass before then.

**Token estimates.** Tokens are counted by a `TokenEstimator`. The default is
deterministic: `ceil(characters / 4)` (`WARDEN_CHARS_PER_TOKEN`) over the canonical JSON
(sorted keys, no whitespace) of the call's name and arguments and of the reply's
`result` or `error`. It needs no model files or network, gives the same count on every
host, and is an estimate, not a model's exact tokenizer; a tokenizer-backed estimator
can be passed to `create_app(token_estimator=...)`.

**Usage ledger.** `WARDEN_USAGE_STORE` picks where usage is booked:

- `memory` (default): per process and lost on restart. Fine for development and hourly
  budgets on a single instance. Counters of ended windows are swept first when the
  table passes 100,000 entries, then the least recently used.
- `database`: one row per budget counter and window in `usage_counters` (calls, tokens,
  window, readable agent/server/tool labels). Reserving locks the call's rows with
  `SELECT ... FOR UPDATE` in a fixed order and writes only if every budget has room;
  settling is a single atomic `UPDATE ... SET tokens = tokens + n`. Rows of past windows
  remain as history (`mcp-warden usage --all`) until pruned. A test runs 8 threads
  through 4 store instances against one PostgreSQL budget of 10 calls and checks that
  exactly 10 are booked (with the row lock removed it overbooks; 48 in one run).

Counters are keyed by the budget's `id`: changing its numbers keeps the usage so far in
the window, renaming it starts afresh.

### Human approval

A call whose decision is `require_approval` is not forwarded. The gateway parks it as an
approval request and answers JSON-RPC error `-32002` with the request's `approval_id`,
`status: "pending"`, `expires_at` and a `Retry-After` hint. A reviewer approves or denies
it, and the agent collects the decision by **repeating the identical call**, so any MCP
client works without changes:

| Request state | What the repeated call gets |
| --- | --- |
| `pending` | `-32002` with the same `approval_id`; no second request is opened |
| `approved` | the call runs once (after rate limits and budgets) and the request becomes `executed` |
| `denied` | `-32001` with the reviewer and their note, for as long as the decision holds |
| `executed` / `expired` | a fresh `pending` request: every execution needs its own approval |

- **One approval, one exact call.** A request is identified by a fingerprint, the
  SHA-256 of the agent, server, tool and canonical arguments (key order and whitespace
  do not matter). An approval cannot be spent on different arguments or by another
  agent, and it is spent by exactly one execution.
- **Expiry.** A request waits `WARDEN_APPROVAL_TTL_SECONDS` (15 minutes) for a
  reviewer. A decision holds for `WARDEN_APPROVAL_DECISION_TTL_SECONDS` (10 minutes): an
  approval unused by then expires, and a denial answers repeats for that long so an
  agent cannot reopen a request it was just refused by retrying. Expiry is computed on
  read, so no background job is needed for correctness.
- **Order in the pipeline.** Approval runs after the rules and before rate limits and
  budgets, so a waiting call spends nothing. The approval is spent last, right before
  forwarding, so an approved call refused by a rate limit keeps its approval for the
  retry. (Two identical approved calls racing each other: one runs; the other may
  already have taken a rate-limit token and budget before finding the approval spent,
  and gets `-32002` for a new request.)
- **Queue cap.** An agent can have at most `WARDEN_APPROVAL_MAX_PENDING_PER_AGENT` (20)
  requests waiting; past that, new requests get `-32003` with `Retry-After`, so a
  looping agent cannot flood reviewers.
- **Optional waiting.** With `WARDEN_APPROVAL_WAIT_SECONDS` > 0 the gateway holds the
  call that long, polling for a decision, and answers with the tool's result if the
  approval arrives in time. The default (0) answers at once, which suits clients with
  short request timeouts.
- **What reviewers see.** The request stores the call's arguments, because a reviewer
  cannot judge a call without them. They are dropped when the request is denied,
  executed or expires, leaving only their digest and size.

**Reviewing.** Two ways to see the queue and decide:

- the admin API (see [Admin API](#admin-api-and-policy-reload) for its tokens):
  `GET /v1/approvals?status=pending&agent=...`, `GET /v1/approvals/{id}`,
  `POST /v1/approvals/{id}/approve` and `.../deny` with `{"note": "..."}`.
  Deciding a request that is not pending is `409`. With a named admin token the decision
  is recorded under that admin's name, and naming someone else as `reviewer` is `403`;
  with the shared token, `reviewer` says who decided (default `admin`);
- `mcp-warden approvals list | show <id> | approve <id> | deny <id>`, working directly
  on the database.

**Where requests live.** `WARDEN_APPROVAL_STORE` picks the store:

- `memory` (default): per process, lost on restart, decided through the admin API only.
  At most 10,000 requests are kept (finished ones are dropped first).
- `database`: the `approval_requests` table, shared by every gateway instance and the
  CLI. Two guarantees of the database carry the concurrency: an `open_key` column holds
  the fingerprint while a request is open and is unique, so identical calls racing to
  open a request create one (the loser retries and finds it); and claiming or deciding
  is a single conditional `UPDATE ... WHERE status = 'approved' AND expires_at > now`,
  so exactly one claim wins and a request is never both approved and denied. Tests run
  8 threads against PostgreSQL for both; without the retry on the unique key, the same
  open race raised 26 integrity errors over 5 rounds.

### Audit log

Every JSON-RPC request the gateway routes to an upstream leaves one audit event,
whatever happened to it: forwarded, denied, parked for approval, rate-limited, over
budget, rejected as invalid, or failed upstream. An event holds **metadata only**:

| Field | Meaning |
| --- | --- |
| `occurred_at`, `latency_ms` | when the request arrived and how long the gateway took to answer it |
| `agent`, `server`, `method`, `tool` | who called what (`tool` for `tools/call` only) |
| `outcome` | `forwarded`, `denied`, `approval_pending`, `rate_limited`, `budget_exhausted`, `upstream_error`, `invalid` or `error` |
| `effect`, `rule_id`, `approval_id` | the policy decision and rule, and the approval request involved |
| `error_code`, `tool_error` | the JSON-RPC error code of the answer (the gateway's or the upstream's), and the tool result's `isError` |
| `arguments_digest`, `arguments_size` | a digest and the byte size of the canonical arguments |

Arguments, results and error messages are never stored: they are where credentials and
personal data end up. The digest still lets an investigator tell whether two calls had
identical arguments, or check a call against arguments they already hold. A plain
SHA-256 of a small argument object such as `{"confirm": true}` can be recovered by
hashing guesses, so set `WARDEN_AUDIT_HASH_KEY` (16+ bytes) to make the digest an
HMAC-SHA-256; without it the gateway logs a warning at startup.

- **Never in the way.** The events of one HTTP request (one message or a whole batch)
  are written in one transaction after the answers are ready. A failed write is
  logged and counted, and the agent still gets its answer: an audit outage does not
  become an agent outage. Notifications are not audited; they carry no decision.
- **Where events live.** `WARDEN_AUDIT_STORE=memory` (default) keeps the newest
  `WARDEN_AUDIT_MEMORY_MAX_EVENTS` (10,000) in process; `database` appends to the
  `audit_events` table, shared by every gateway and readable from the CLI; `off`
  disables auditing.
- **Querying.** `GET /v1/audit` (admin token required) and `mcp-warden audit` list events
  newest first, filtered by `agent`, `server`, `tool`, `method`, `outcome`, `since`
  (inclusive) and `until` (exclusive). Pages use keyset pagination on
  `(occurred_at, id)`: pass `next_cursor` back as `cursor`. Events written while
  someone pages never shift or repeat entries, and every page is one index range scan
  however deep it is.

### Retention

`mcp-warden retention` (for cron or a Kubernetes CronJob), or the gateway itself every
`WARDEN_RETENTION_INTERVAL_SECONDS` (off by default), deletes history older than
`WARDEN_RETENTION_DAYS` (30): audit events, approval requests that finished (executed,
expired, or denied with the denial no longer in force), and budget counters of windows
that ended. Rate-limit buckets that have refilled are deleted whatever their age, since
a full bucket and a missing row mean the same thing. Each step is one `DELETE`, safe to
run from several places at once; a failed run in the gateway is logged and retried at
the next interval. The in-memory stores bound themselves and need no job.

### Agent identity

Every request to `/mcp/{server}` is authenticated first; until it is, the gateway does
not even reveal whether the server exists. Agents send a per-agent API key as
`Authorization: Bearer mcpw_<prefix>_<secret>`:

- `prefix` is 12 random hex characters stored in clear, used to find the key and to
  identify it in listings; `secret` is 32 random bytes (URL-safe base64).
- Only `sha256(key)` is stored. The secret has 256 bits of entropy, so a slow password
  hash would add latency without adding protection. Digests are compared with
  `hmac.compare_digest`, and an unknown prefix costs the same hashing work as a wrong
  secret.
- Keys can expire, be revoked, or stop working because their agent is disabled. All of
  these fail with the same `401` and JSON-RPC error `-32008` plus
  `WWW-Authenticate: Bearer realm="mcp-warden"`, so a caller learns nothing about which
  keys or agents exist. Revocation takes effect on the next request.
- `last_used_at` is updated at most once a minute per key, so busy agents do not turn
  every call into a database write.
- The resolved agent name is what the policy is evaluated against. The agent's key is
  never forwarded to an upstream.

Agents and keys live in the database (`WARDEN_DATABASE_URL`; SQLite by default,
PostgreSQL via `uv sync --extra postgres` and a `postgresql+psycopg://` URL). Schema
changes are Alembic migrations shipped inside the package; `mcp-warden db upgrade`
applies them, and the gateway refuses to start on a database that is not at the latest
revision instead of failing on the first request.

For local development the gateway can instead trust an `X-Warden-Agent` header
(`WARDEN_AUTH_MODE=trusted-header`; missing means `anonymous`). That header is only as
trustworthy as whatever sets it, so use this mode only behind an authenticating proxy.

Not yet proxied: the optional `GET` stream for server-initiated messages and `DELETE`
session teardown (both answered with `405`, which MCP allows), and server-to-client
messages interleaved on a POST's SSE stream, which are currently dropped.

### Admin API and policy reload

Everything under `/v1` is for operators and needs an admin token as
`Authorization: Bearer <token>`. Two kinds exist, and with neither configured the admin
API answers `503`, so a gateway is never manageable by whoever can reach it:

- **Named tokens**, `WARDEN_ADMIN_TOKENS='{"alice": "...", "bob": "..."}'`: one per
  person or system. The name is what approval decisions record and what the gateway
  logs for every change, so a reviewer cannot sign as someone else.
- **The shared token**, `WARDEN_ADMIN_TOKEN`: one token for a small setup; its holder is
  called `admin` and names the reviewer per decision.

Tokens must be at least 16 characters and distinct, and names are checked at startup.
A supplied token is hashed with SHA-256 and compared against every configured digest
with `hmac.compare_digest`, without stopping at the first match, so response times
reveal neither which tokens exist nor how much of one was guessed. Agent API keys are
never admin credentials.

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/policy` | The policy in force: rules, limits, budgets, and its source (path, SHA-256, load time, last reload error) |
| `POST /v1/policy/evaluate` | Dry-run a decision without calling an upstream |
| `POST /v1/policy/reload` | Re-read, validate and swap in the policy file; reports what changed |
| `GET, POST /v1/agents` | List agents, register one (`{"name", "description"}`) |
| `GET /v1/agents/{name}` | An agent with all its keys (prefix, status, expiry, last use) |
| `POST /v1/agents/{name}/disable`, `.../enable` | Switch all of an agent's keys off or on, effective on the next request |
| `GET, POST /v1/agents/{name}/keys` | List keys, issue one (`{"label", "expires_in_days"}`) |
| `POST /v1/keys/{prefix}/revoke` | Revoke a key |
| `GET /v1/usage?agent=&all=` | Budget counters (open windows unless `all=true`) with the limits of the policy in force |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve`, `.../deny` | The approval queue (see [Human approval](#human-approval)) |
| `GET /v1/audit` | The audit log (see [Audit log](#audit-log)) |

An issued key's plaintext appears once, in the response that creates it, sent with
`Cache-Control: no-store`. The agent and key endpoints need the identity database
(`WARDEN_AUTH_MODE=api-key`) and answer `404` in trusted-header mode. The CLI covers the
same ground: `agents`, `keys`, `usage`, `approvals` and `audit` work directly on the
database, and `mcp-warden policy show | reload` drives a running gateway, reading the
token from `WARDEN_ADMIN_TOKEN` (never a flag, so it stays out of shell history) and the
address from `--gateway` or `WARDEN_GATEWAY_URL`.

**Reloading the policy.** Changing a rule should not drop every MCP session and parked
approval, so the policy file can be reloaded into a running gateway:

- A reload reads the file, validates all of it and only then swaps it in. A file that
  does not parse or validate never replaces a working policy: the request fails with
  `422` and the error, the gateway keeps enforcing the last good version, and
  `GET /v1/policy` shows the failure until a later reload succeeds.
- Files are compared by SHA-256 of their content, so an unchanged file is a no-op and a
  `touch` is not a reload. The response lists the rules, rate limits and budgets that
  were added, removed or changed, and whether the default changed.
- `WARDEN_POLICY_RELOAD_INTERVAL_SECONDS` (off by default) makes the gateway check the
  file itself, e.g. when a Kubernetes ConfigMap is updated in place. A failed check is
  logged and the current policy stays.
- The engine reads its policy once per evaluation, so a request is never judged against
  a mix of two versions. The new policy applies from the next request, also in sessions
  that are already open. Rate-limit buckets and budget counters are keyed by limit id,
  so an edited limit keeps its consumption and a removed one stops counting; a parked
  approval only matters if the new policy still requires approval for the call.

### Observability

The gateway reports what it decides through three channels, all built so that tool
arguments, results, error messages and MCP session ids never leave it.

**Metrics.** `GET /metrics` serves Prometheus text format. Most series are derived from
the same per-request events the audit log is built from, so a dashboard and the audit
trail cannot disagree, and they keep working with `WARDEN_AUDIT_STORE=off`.

| Metric | Labels | What it shows |
| --- | --- | --- |
| `mcp_warden_requests_total`, `mcp_warden_request_duration_seconds` | server, method, outcome | Every JSON-RPC request and how long the gateway took to answer it |
| `mcp_warden_tool_calls_total` | agent, server, tool, outcome | `tools/call` by result: forwarded, denied, approval_pending, rate_limited, budget_exhausted, upstream_error, ... |
| `mcp_warden_policy_decisions_total` | agent, server, effect, rule | Which rule decided (`default` when none matched) |
| `mcp_warden_tool_errors_total` | server, tool | Forwarded calls whose result had `isError` |
| `mcp_warden_upstream_requests_total`, `mcp_warden_upstream_duration_seconds` | server, result | The upstream leg: `ok` or the failure kind (`unreachable`, `timeout`, `http_status`, `invalid_response`, `too_large`, `session_lost`) |
| `mcp_warden_budget_calls_total`, `mcp_warden_budget_tokens_total`, `mcp_warden_budget_refusals_total` | budget, agent (, exhausted) | What was booked against each budget and what it refused |
| `mcp_warden_http_rejections_total` | reason | Requests refused before any message was handled (unauthenticated, unknown server, oversized, ...) |
| `mcp_warden_http_requests_total`, `mcp_warden_http_request_duration_seconds` | route, method, status | Every HTTP route, admin API included, by route template |
| `mcp_warden_policy_info`, `_rules`, `_reloads_total`, `_reload_failures_total`, `_reload_error`, `_loaded_timestamp_seconds` | | The policy in force and its reloads; `reload_error` is 1 while a broken edit is being refused |
| `mcp_warden_audit_events_written_total`, `mcp_warden_audit_write_failures_total` | | The audit log is fail-open, so alert on failures |
| `mcp_warden_metric_label_overflow_total` | label | Label values folded into `__other__` |

Every series lives in a registry owned by one gateway, never the process-global one.
Labels fed by agents are bounded, because an agent calling a million made-up tool names
must not create a million time series: methods that are not MCP methods are reported as
`other`, and agents, tools and rules beyond `WARDEN_METRICS_MAX_LABEL_VALUES` distinct
values (1000 by default) as `__other__`, counted in the overflow metric. HTTP routes are
labelled by template (`/mcp/{server}`), never by raw path. State that already lives
somewhere (the policy in force, reload and audit counters) is read at scrape time rather
than copied into gauges that could drift. Set `WARDEN_METRICS_TOKEN` to require
`Authorization: Bearer <token>` on `/metrics`, or `WARDEN_METRICS_ENABLED=false` to
turn metrics off.

**Traces.** With `pip install 'mcp-warden[otel]'` and `WARDEN_TRACING=otlp` (or
`console` to try it), each JSON-RPC request becomes a `SERVER` span named
`tools/call <tool>` (or the method), with the decision as attributes: `mcp.method.name`,
`gen_ai.tool.name`, `mcp.protocol.version`, `mcp_warden.agent`, `mcp_warden.outcome`,
`mcp_warden.policy.effect`, `mcp_warden.policy.rule_id`, `mcp_warden.approval.id` and the
JSON-RPC error code. Child spans cover the stages that can wait (`mcp_warden.approval`,
`mcp_warden.rate_limit`, `mcp_warden.budget`) and the upstream leg (`POST <server>`,
`CLIENT`), which records only the upstream's host and port, never its URL, since URLs
can carry credentials.

Context propagation is W3C Trace Context in both directions: a `traceparent` sent by the
agent becomes the parent of the gateway's spans, and the upstream receives the gateway's
own `traceparent`, so one trace covers agent, gateway and MCP server. Refusals are
annotated, not marked as errors, since a denied call is the gateway doing its job; an
upstream failure marks both spans as errors. The gateway's code depends only on
`opentelemetry-api`, so without the extra (or with `WARDEN_TRACING=off`, the default)
every span is a no-op. The provider is built per gateway rather than installed globally;
`WARDEN_OTLP_ENDPOINT` (an OTLP/HTTP traces URL), `WARDEN_SERVICE_NAME` and
`WARDEN_TRACE_SAMPLE_RATIO` (parent-based) configure it, and the SDK's own
`OTEL_EXPORTER_OTLP_*` variables work too.

**Logs.** `WARDEN_LOG_FORMAT=json` writes one JSON object per line for the gateway and
uvicorn. A line logged inside a span carries `trace_id` and `span_id`, fields passed with
`extra=` are kept, and access log lines are split into `client`, `method`, `path` and
`status`. The default `text` format is for terminals.

From a local run (fake upstream on port 9001, an API key for `support-bot`, the audit log
in SQLite, `WARDEN_LOG_FORMAT=json WARDEN_TRACING=console`): an initialize, an allowed
`add` sent with a `traceparent`, and a `delete_records` call the policy denies. The
gateway's first log lines:

```json
{"ts": "2026-10-21T10:08:10.502Z", "level": "warning", "logger": "mcp_warden.app", "message": "audit argument digests are plain SHA-256; set WARDEN_AUDIT_HASH_KEY so that small arguments cannot be recovered by guessing"}
{"ts": "2026-10-21T10:08:10.522Z", "level": "info", "logger": "uvicorn.error", "message": "Started server process [3596]"}
```

The span for the allowed call continues the agent's trace (`4bf92f...`, parent
`00f067...`), trimmed to the interesting fields:

```json
{
    "name": "tools/call add",
    "context": {"trace_id": "0x4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "0x11713a5088acb65e"},
    "kind": "SpanKind.SERVER",
    "parent_id": "0x00f067aa0ba902b7",
    "status": {"status_code": "UNSET"},
    "attributes": {
        "mcp.method.name": "tools/call",
        "mcp_warden.agent": "support-bot",
        "mcp_warden.server": "demo",
        "mcp.protocol.version": "2025-11-25",
        "mcp_warden.outcome": "forwarded",
        "gen_ai.tool.name": "add",
        "gen_ai.operation.name": "execute_tool",
        "mcp_warden.policy.effect": "allow",
        "mcp_warden.policy.rule_id": "demo-basics",
        "mcp_warden.tool.is_error": false
    }
}
```

And `curl -s localhost:8080/metrics`, filtered to a few series:

```text
mcp_warden_requests_total{method="initialize",outcome="forwarded",server="demo"} 1.0
mcp_warden_requests_total{method="tools/call",outcome="forwarded",server="demo"} 1.0
mcp_warden_requests_total{method="tools/call",outcome="denied",server="demo"} 1.0
mcp_warden_tool_calls_total{agent="support-bot",outcome="forwarded",server="demo",tool="add"} 1.0
mcp_warden_tool_calls_total{agent="support-bot",outcome="denied",server="demo",tool="delete_records"} 1.0
mcp_warden_policy_decisions_total{agent="support-bot",effect="allow",rule="demo-basics",server="demo"} 1.0
mcp_warden_policy_decisions_total{agent="support-bot",effect="deny",rule="never-destructive",server="demo"} 1.0
mcp_warden_upstream_requests_total{result="ok",server="demo"} 2.0
mcp_warden_upstream_duration_seconds_count{server="demo"} 2.0
mcp_warden_build_info{version="0.1.0"} 1.0
mcp_warden_policy_info{sha256="aac81c906083",version="1"} 1.0
mcp_warden_policy_rules 9.0
mcp_warden_policy_reload_error 0.0
mcp_warden_audit_events_written_total 3.0
```

The denied call has a span and a metric but no upstream request: it never left the
gateway.

## Try it with Docker Compose

The fastest way to see the gateway work: PostgreSQL, the migrations, the fake MCP server
and the gateway in one stack, plus a scripted agent that walks through every feature.

```bash
git clone https://github.com/xeeshan16/mcp-warden.git
cd mcp-warden
scripts/demo.sh
```

`scripts/demo.sh` writes a `.env` with random secrets the first time (see
[`.env.example`](.env.example); `.env` is git-ignored), runs
`docker compose up --build --detach` and then the demo agent with
`docker compose --profile demo run --rm demo`. The gateway stays up on
`http://127.0.0.1:8080` (loopback only) for the admin API, `curl` and the CLI's
`policy` and `demo` commands; `export $(grep WARDEN_ADMIN_TOKEN .env)` gives them the
admin token.
`docker compose --profile demo down --volumes` removes everything again.

What the stack runs ([`compose.yaml`](compose.yaml)):

| Service | Image | Role |
| --- | --- | --- |
| `postgres` | `postgres:16-alpine` | Agents, keys, rate-limit buckets, budget ledger, approvals, audit log |
| `migrate` | `mcp-warden:local` | One-shot `mcp-warden db upgrade`; the gateway starts after it succeeds |
| `upstream` | `mcp-warden:local` | `mcp-warden fake-upstream`, registered as `demo` in [`deploy/upstreams.yaml`](deploy/upstreams.yaml) |
| `warden` | `mcp-warden:local` | The gateway: API keys, every store on PostgreSQL, keyed audit digests, JSON logs, policy hot reload |
| `demo` | `mcp-warden:local` | `mcp-warden demo` (profile `demo`, run on demand) |

The policy is [`examples/policy.yaml`](examples/policy.yaml), mounted read-only with its
directory; edit it and the gateway reloads it within five seconds (a broken edit is
refused and the previous policy stays in force). The [`Dockerfile`](Dockerfile) builds
the locked dependencies with uv in a first stage and copies only the virtual environment
into a slim runtime image, which runs as an unprivileged user with a `/healthz` health
check; Compose adds a read-only root filesystem, no Linux capabilities and
`no-new-privileges`.

The demo agent plays both sides: an operator using the admin API and an MCP client
using the key the operator issued. Each step states what it expects, so the script is
also a smoke test that exits non-zero when the gateway behaves differently; CI builds the
image, starts the stack and runs it twice (agents are reused and the approval is unique
per run, so it can be repeated). It also works against any gateway that serves the
example policy with the fake upstream as `demo`:
`WARDEN_ADMIN_TOKEN=... uv run mcp-warden demo --gateway http://127.0.0.1:8080`.

Output of the first demo run in CI, against the Compose stack built from this
repository ([run 12](https://github.com/xeeshan16/mcp-warden/actions/runs/39759880584),
Compose progress lines trimmed). Ids and keys differ on every run.

```text
$ docker compose --profile demo run --rm demo
 Container mcp-warden-postgres-1  Healthy
 Container mcp-warden-upstream-1  Healthy
 Container mcp-warden-migrate-1  Exited
MCP Warden demo against http://warden:8080 (server 'demo', run 68498f)

▶ Operator onboards agent 'support-bot' and issues an API key
  ✔ agent support-bot created
  ✔ key 88d9b37ef3e8… issued (the full key is shown once, never stored)

▶ Agent opens an MCP session through the gateway
  ✔ connected to mcp-warden-fake-upstream 1.0.0, protocol 2025-11-25

▶ tools/list only shows what the policy could allow
  ✔ visible: echo, add, get_forecast, create_ticket, sleep (delete_records is hidden)

▶ Allowed calls are forwarded
  ✔ get_forecast → {"city": "Lisbon", "condition": "fog", "high_c": 25, "synthetic": true}  [rule read-only-everywhere]
  ✔ add 2 + 40 → 42  [rule demo-basics]

▶ Denied calls never reach the upstream
  ✔ delete_records → -32001 denied by rule never-destructive
  ✔ sleep 10s → -32001 denied by argument rule short-sleeps-only

▶ A risky call waits for a human
  ✔ urgent create_ticket → -32002 pending approval apr_ab4855d71b9d11707ba3f355
  ✔ operator approves it (decided by admin)
  ✔ agent repeats the identical call → created ticket T-F7AE07CF

▶ A burst of ticket creation hits the rate limit
  ✔ call 1 → created ticket T-0741E34F
  ✔ call 2 → created ticket T-521DD883
  ✔ call 3 → -32003 rate limited by demo-tickets, retry after 20s

▶ Revoking the key cuts the agent off on its next request
  ✔ key 88d9b37ef3e8… revoked; the next call gets HTTP 401

▶ The audit log has the metadata of every call, never the payloads
    tool            outcome          rule                          args
    get_forecast    forwarded        read-only-everywhere           17B
    add             forwarded        demo-basics                    14B
    delete_records  denied           never-destructive              21B
    sleep           denied           short-sleeps-only              14B
    create_ticket   approval_pending urgent-tickets-need-a-human    62B
    create_ticket   forwarded        urgent-tickets-need-a-human    62B
    create_ticket   forwarded        support-bot-demo-tickets       28B
    create_ticket   forwarded        support-bot-demo-tickets       28B
    create_ticket   rate_limited     support-bot-demo-tickets       28B
  ✔ 9 tool calls recorded with argument digests and sizes only

▶ Prometheus metrics count the decisions
    mcp_warden_policy_decisions_total{agent="support-bot",effect="allow",rule="demo-basics",server="demo"} 1.0
    mcp_warden_policy_decisions_total{agent="support-bot",effect="allow",rule="read-only-everywhere",server="demo"} 1.0
    mcp_warden_policy_decisions_total{agent="support-bot",effect="allow",rule="support-bot-demo-tickets",server="demo"} 3.0
    mcp_warden_policy_decisions_total{agent="support-bot",effect="deny",rule="never-destructive",server="demo"} 1.0
    mcp_warden_policy_decisions_total{agent="support-bot",effect="deny",rule="short-sleeps-only",server="demo"} 1.0
    mcp_warden_policy_decisions_total{agent="support-bot",effect="require_approval",rule="urgent-tickets-need-a-human",server="demo"} 2.0
  ✔ 6 decision series exported

10 of 10 steps behaved as expected
```

The second run in the same job reused the agent and, because the first run had just
used up the ticket rate limit, waited it out before collecting its approval:

```text
▶ Operator onboards agent 'support-bot' and issues an API key
  ✔ agent support-bot already exists; reusing it
  ...
▶ A risky call waits for a human
  ✔ urgent create_ticket → -32002 pending approval apr_8caeccfb4f5a9857c1cee248
  ✔ operator approves it (decided by admin)
    (rate limited from an earlier run; waiting 16s)
  ✔ agent repeats the identical call → created ticket T-EEE4A80C
  ...
10 of 10 steps behaved as expected
```

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/xeeshan16/mcp-warden.git
cd mcp-warden
uv sync

# Validate a policy and dry-run a decision
uv run mcp-warden check examples/policy.yaml \
  --agent ci-bot --server github --tool delete_repo

# Create the identity database (SQLite at ./mcp-warden.db unless WARDEN_DATABASE_URL is set)
uv run mcp-warden db upgrade

# Dry-run a decision over HTTP (the /v1 admin API needs an admin token)
export WARDEN_ADMIN_TOKEN=$(openssl rand -hex 24)
uv run mcp-warden serve --policy examples/policy.yaml
curl -s localhost:8080/v1/policy/evaluate \
  -H "authorization: Bearer $WARDEN_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"agent":"ci-bot","server":"github","tool":"create_pull_request"}'
```

### Register an agent and issue it a key

```bash
uv run mcp-warden agents create support-bot --description "Answers support tickets"
uv run mcp-warden keys issue support-bot --label laptop --expires-in-days 30
# prints the key once on stdout; store it, e.g. export WARDEN_KEY=mcpw_...
uv run mcp-warden keys list support-bot
uv run mcp-warden keys revoke <prefix>
```

Output from a local run against a fresh SQLite database, with the fake upstream and the
gateway running as below (the key's secret part is elided here):

```text
$ mcp-warden serve            # before the migration
error: database schema is at an empty database, expected 0001; run `mcp-warden db upgrade`
$ mcp-warden db upgrade
database at revision 0001
$ mcp-warden agents create support-bot --description "Answers support tickets"
created agent support-bot
$ mcp-warden keys issue support-bot --label laptop --expires-in-days 30
mcpw_a02556cf1df0_…
issued key a02556cf1df0 for support-bot (expires 2026-11-14T09:58:13Z). It is shown only once; store it now.

$ tools/list without a key
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer realm="mcp-warden"
{"jsonrpc":"2.0","id":null,"error":{"code":-32008,"message":"missing bearer API key"}}
$ tools/list with the support-bot key
['echo', 'add', 'get_forecast', 'create_ticket', 'sleep']

$ mcp-warden keys revoke a02556cf1df0
revoked key a02556cf1df0 of support-bot at 2026-10-15T09:58:17Z
$ tools/list with the revoked key
{"jsonrpc":"2.0","id":null,"error":{"code":-32008,"message":"invalid, expired or revoked API key"}}
$ mcp-warden keys list support-bot
a02556cf1df0	revoked	created 2026-10-15T09:58:13Z	expires 2026-11-14T09:58:13Z	last used 2026-10-15T09:58:16Z	laptop
```

### Proxy a session to the fake MCP server

The requests below authenticate with a key from the previous step. The outputs further
down were captured before API keys were added, when the agent came from the
`X-Warden-Agent` header (today's `WARDEN_AUTH_MODE=trusted-header`).

```bash
# Terminal 1: the deterministic fake upstream (add --sse to answer with event streams)
uv run mcp-warden fake-upstream --port 9001

# Terminal 2: the gateway, with examples/upstreams.yaml pointing "demo" at it
uv run mcp-warden serve

# Terminal 3: an MCP session through the gateway
curl -si localhost:8080/mcp/demo -H 'content-type: application/json' \
  -H "authorization: Bearer $WARDEN_KEY" -d \
  '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
# copy the mcp-session-id response header, then:
curl -s localhost:8080/mcp/demo -H 'content-type: application/json' \
  -H "authorization: Bearer $WARDEN_KEY" \
  -H 'mcp-session-id: fake-session-1' -H 'mcp-protocol-version: 2025-11-25' -d \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_forecast","arguments":{"city":"Lahore"}}}'
```

Output from a local run:

```text
HTTP/1.1 200 OK
mcp-session-id: fake-session-1
{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"mcp-warden-fake-upstream","version":"1.0.0"}}}

{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"city\": \"Lahore\", \"condition\": \"fog\", \"high_c\": 14, \"synthetic\": true}"}],"isError":false,"structuredContent":{"city":"Lahore","condition":"fog","high_c":14,"synthetic":true}}}
```

With the fake upstream stopped, the same call returns
`{"jsonrpc":"2.0","id":3,"error":{"code":-32005,"message":"upstream unreachable","data":{"server":"demo"}}}`.

The example policy applies to that session too. Output from a local run with the same
two servers (the session id from `initialize` in `mcp-session-id`; error bodies were
pretty-printed and are wrapped here for width):

```text
$ tools/list (no X-Warden-Agent header, so agent "anonymous")
['echo', 'add', 'get_forecast', 'sleep']
$ tools/list with X-Warden-Agent: support-bot
['echo', 'add', 'get_forecast', 'create_ticket', 'sleep']

$ tools/call delete_records {"table": "users"} as support-bot
{"jsonrpc": "2.0", "id": 2, "error": {"code": -32001,
  "message": "tool call denied by policy: delete_records",
  "data": {"server": "demo", "tool": "delete_records", "effect": "deny",
           "rule_id": "never-destructive",
           "reason": "Destructive tools are never allowed through the gateway."}}}

$ tools/call sleep {"seconds": 30}
{"jsonrpc": "2.0", "id": 3, "error": {"code": -32001,
  "message": "tool call denied by policy: sleep",
  "data": {"server": "demo", "tool": "sleep", "effect": "deny",
           "rule_id": "short-sleeps-only",
           "reason": "Calls that would hold an upstream worker for more than two seconds."}}}

$ tools/call sleep {"seconds": 1}
{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"slept 1s"}],"isError":false}}
```

The fake upstream's log showed four requests (`initialize`, two `tools/list`, one
`sleep`): the two denied calls never left the gateway.

### See a rate limit trip

With the example policy, `support-bot` may create three demo tickets a minute. Output
from a local run with both servers as above, a support-bot key in `$WARDEN_KEY`,
`WARDEN_RATE_LIMIT_STORE=database` and a local PostgreSQL in `WARDEN_DATABASE_URL`
(response bodies trimmed to the lines shown):

```text
$ mcp-warden db upgrade
database at revision 0002
$ mcp-warden check examples/policy.yaml --agent support-bot --server demo --tool create_ticket
ok: examples/policy.yaml (version 1, 8 rules, 3 rate limits, default deny)
deny: support-bot -> demo/create_ticket (rule <default>: no rule matched; default is deny)
rate limit per-agent: 120/minute, burst 30, per agent
rate limit demo-tickets: 3/minute, burst 3, per tool

$ tools/call create_ticket #1 .. #3   (each with a title)
HTTP/1.1 200 OK
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"created ticket T-542B6222"}],"isError":false}}
...
$ tools/call create_ticket #4
HTTP/1.1 200 OK
retry-after: 20
{"jsonrpc":"2.0","id":4,"error":{"code":-32003,"message":"rate limit exceeded: demo-tickets","data":{"server":"demo","tool":"create_ticket","limit_id":"demo-tickets","scope":"tool","requests":3,"per":"minute","burst":3,"retry_after":20}}}

$ psql -c "select tokens, full_at - updated_at as seconds_to_full from rate_limit_buckets"
 tokens | seconds_to_full
--------+-----------------
  0.002 |            60.0
 27.080 |             1.5
```

(The dry run says `deny` because the support-bot ticket rule has an argument matcher on
`title` and the dry run had no arguments; the real calls carried a title.) The fake
upstream logged four requests, `initialize` and the three allowed calls; the fourth
call never left the gateway.

### See a budget run out

With the example policy, each agent may call `echo` on the demo server 50 times an
hour (`demo-echo`). Output from a local run with both servers as above, a support-bot
key, `WARDEN_USAGE_STORE=database`, `WARDEN_RATE_LIMIT_STORE=database` and a fresh local
PostgreSQL database in `WARDEN_DATABASE_URL`; the 50 calls were spaced 0.6 s apart to
stay under the `per-agent` rate limit:

```text
$ mcp-warden db upgrade
database at revision 0003
$ tools/call echo {"text": "hello 1"} .. {"text": "hello 50"}
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello 1"}],"isError":false}}
...
{"jsonrpc":"2.0","id":50,"result":{"content":[{"type":"text","text":"hello 50"}],"isError":false}}
$ tools/call echo {"text": "hello 51"}
HTTP/1.1 200 OK
retry-after: 3482
{"jsonrpc":"2.0","id":51,"error":{"code":-32004,"message":"budget exhausted: demo-echo","data":{"server":"demo","tool":"echo","budget_id":"demo-echo","scope":"tool","window":"hour","exhausted":"calls","used":50,"limit":50,"resets_at":"2026-10-17T11:00:00Z","retry_after":3482}}}
$ tools/call add {"a": 2, "b": 3}
{"jsonrpc":"2.0","id":52,"result":{"content":[{"type":"text","text":"5"}],"isError":false,"structuredContent":{"sum":5}}}

$ mcp-warden usage
budget	agent	server/tool	window	calls	tokens
demo-echo	support-bot	demo/echo	2026-10-17T10:00:00Z..2026-10-17T11:00:00Z	50	1400
daily-calls	support-bot	*	2026-10-17T00:00:00Z..2026-10-18T00:00:00Z	51	1432
support-bot-tokens	support-bot	*	2026-10-17T00:00:00Z..2026-10-18T00:00:00Z	51	1432
```

`add` still works because `demo-echo` is scoped to the tool, while the agent-wide
budgets count both tools. The fake upstream logged 52 requests (`initialize`, 50 echoes
and the `add`); the 51st echo never left the gateway.

### Approve a parked call

The example policy sends `support-bot`'s urgent tickets to a human
(`urgent-tickets-need-a-human`). Output from a local run with both servers as above, a
support-bot key, `WARDEN_APPROVAL_STORE=database`, `WARDEN_ADMIN_TOKEN` set and a fresh
local PostgreSQL database in `WARDEN_DATABASE_URL`:

```text
$ mcp-warden db upgrade
database at revision 0004
$ tools/call create_ticket {"title": "Checkout is down", "priority": "urgent"}
HTTP/1.1 200 OK
retry-after: 5
{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"tool call requires human approval: create_ticket","data":{"server":"demo","tool":"create_ticket","effect":"require_approval","rule_id":"urgent-tickets-need-a-human","reason":"An urgent ticket pages someone, so a person signs it off first.","approval_id":"apr_05761497c50ebe50647a9d46","status":"pending","expires_at":"2026-10-18T10:19:48Z","retry_after":5}}}

$ mcp-warden approvals list
id	status	agent	server/tool	rule	created	expires
apr_05761497c50ebe50647a9d46	pending	support-bot	demo/create_ticket	urgent-tickets-need-a-human	2026-10-18T10:04:48Z	2026-10-18T10:19:48Z

$ curl -X POST localhost:8080/v1/approvals/apr_05761497c50ebe50647a9d46/approve \
    -H "authorization: Bearer $WARDEN_ADMIN_TOKEN" -H 'content-type: application/json' \
    -d '{"reviewer":"alice","note":"on-call confirmed the outage"}'
{"id":"apr_05761497c50ebe50647a9d46","status":"approved","agent":"support-bot","server":"demo","tool":"create_ticket","rule_id":"urgent-tickets-need-a-human","reason":"An urgent ticket pages someone, so a person signs it off first.","arguments":{"priority":"urgent","title":"Checkout is down"},"arguments_digest":"a96e1602c823d2e771d1d550d873d9d210ac400acf0f44b7cba913e06cf3a51b","arguments_size":48,"created_at":"2026-10-18T10:04:48Z","expires_at":"2026-10-18T10:14:50Z","decided_at":"2026-10-18T10:04:50Z","decided_by":"alice","note":"on-call confirmed the outage","executed_at":null}

$ the same tools/call again
HTTP/1.1 200 OK
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"created ticket T-13158DF0"}],"isError":false}}

$ and once more (an approval covers one execution)
{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"tool call requires human approval: create_ticket","data":{"server":"demo","tool":"create_ticket","effect":"require_approval","rule_id":"urgent-tickets-need-a-human","reason":"An urgent ticket pages someone, so a person signs it off first.","approval_id":"apr_ee72ffd4a71dfdeb34692bb0","status":"pending","expires_at":"2026-10-18T10:19:50Z","retry_after":5}}}

$ mcp-warden approvals deny apr_ee72ffd4a71dfdeb34692bb0 --reviewer bob --note 'duplicate of the first ticket'
denied apr_ee72ffd4a71dfdeb34692bb0: support-bot -> demo/create_ticket (valid until 2026-10-18T10:14:52Z)
$ the same tools/call again
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"tool call denied by a reviewer: create_ticket","data":{"server":"demo","tool":"create_ticket","effect":"require_approval","rule_id":"urgent-tickets-need-a-human","reason":"An urgent ticket pages someone, so a person signs it off first.","approval_id":"apr_ee72ffd4a71dfdeb34692bb0","status":"denied","decided_by":"bob","note":"duplicate of the first ticket"}}}

$ mcp-warden approvals list --status all
id	status	agent	server/tool	rule	created	expires
apr_ee72ffd4a71dfdeb34692bb0	denied	support-bot	demo/create_ticket	urgent-tickets-need-a-human	2026-10-18T10:04:50Z	2026-10-18T10:14:52Z
apr_05761497c50ebe50647a9d46	executed	support-bot	demo/create_ticket	urgent-tickets-need-a-human	2026-10-18T10:04:48Z	2026-10-18T10:14:50Z
```

The fake upstream logged two requests, `initialize` and the one approved ticket.

### Query the audit log

Output from a local run with both servers as above, a support-bot key,
`WARDEN_AUDIT_STORE=database`, `WARDEN_AUDIT_HASH_KEY` and `WARDEN_ADMIN_TOKEN` set,
and a fresh local PostgreSQL database in `WARDEN_DATABASE_URL`. After `initialize`, the
agent created a ticket titled "Customer 4711 cannot log in", tried `delete_records`,
asked for an urgent ticket, added two numbers and called `echo` without its argument:

```text
$ mcp-warden audit --limit 3
time	agent	server/tool	outcome	rule	code	ms	args
2026-10-19T10:04:36.238Z	support-bot	demo/echo	forwarded (isError)	demo-basics	-	4.5	9f69e91b55de..(2B)
2026-10-19T10:04:36.216Z	support-bot	demo/add	forwarded	demo-basics	-	3.9	eb19a1a40644..(13B)
2026-10-19T10:04:36.188Z	support-bot	demo/create_ticket	approval_pending	urgent-tickets-need-a-human	-32002	11.3	37b11b1a18b3..(48B)
more: --cursor eyJ0IjoiMjAyNi0xMC0xOVQxMDowNDozNi4xODgxMDArMDA6MDAiLCJpZCI6ImV2dF83MGU5YzNlODhiYmQ4MDBmNGUzNDZjZjAifQ

$ mcp-warden audit --limit 3 --cursor eyJ0IjoiMjAyNi0xMC0xOVQxMDowNDozNi4xODgxMDArMDA6MDAiLCJpZCI6ImV2dF83MGU5YzNlODhiYmQ4MDBmNGUzNDZjZjAifQ
time	agent	server/tool	outcome	rule	code	ms	args
2026-10-19T10:04:36.169Z	support-bot	demo/delete_records	denied	never-destructive	-32001	0.3	cba849695b61..(17B)
2026-10-19T10:04:36.144Z	support-bot	demo/create_ticket	forwarded	support-bot-demo-tickets	-	5.6	510727722120..(39B)
2026-10-19T10:04:36.108Z	support-bot	demo initialize	forwarded	-	-	9.7	-

$ curl 'localhost:8080/v1/audit?tool=create_ticket&limit=1' -H "authorization: Bearer $WARDEN_ADMIN_TOKEN"
{"events":[{"id":"evt_70e9c3e88bbd800f4e346cf0","occurred_at":"2026-10-19T10:04:36.188100+00:00","agent":"support-bot","server":"demo","method":"tools/call","tool":"create_ticket","outcome":"approval_pending","effect":"require_approval","rule_id":"urgent-tickets-need-a-human","approval_id":"apr_462fe9c1024714ef5345d681","error_code":-32002,"tool_error":null,"latency_ms":11.344,"arguments_digest":"37b11b1a18b35f75e90acdfbca7bd2b3c1d8f60a528a3c8bdbf84a15cd2356c7","arguments_size":48}],"next_cursor":"eyJ0IjoiMjAyNi0xMC0xOVQxMDowNDozNi4xODgxMDArMDA6MDAiLCJpZCI6ImV2dF83MGU5YzNlODhiYmQ4MDBmNGUzNDZjZjAifQ"}

$ psql -c "select count(*) from audit_events a where row_to_json(a)::text like '%4711%'"
 count 
-------
     0
(1 row)

$ mcp-warden retention --days 30
removed 0 audit events, 0 approval requests and 0 usage counters older than 2026-09-19T10:04:45Z, and 0 refilled rate-limit buckets
```

### Manage agents and reload the policy over HTTP

Output from a local run with both servers as above, a copy of the example policy in
`policy.yaml`, `WARDEN_USAGE_STORE=database`, two named admins in `WARDEN_ADMIN_TOKENS`
(`alice` and `bob`) and a fresh local PostgreSQL database in `WARDEN_DATABASE_URL`. Alice
onboards the support bot over HTTP (the key's secret part is elided here, and of the
issuing response's headers only `cache-control` is shown):

```text
$ curl -X POST localhost:8080/v1/agents -H "authorization: Bearer $ALICE_TOKEN" \
    -H 'content-type: application/json' -d '{"name":"support-bot","description":"Tier 1 support"}'
{"name":"support-bot","description":"Tier 1 support","disabled":false,"created_at":"2026-10-20T10:06:49Z"}

$ curl -i -X POST localhost:8080/v1/agents/support-bot/keys -H "authorization: Bearer $ALICE_TOKEN" \
    -H 'content-type: application/json' -d '{"label":"prod","expires_in_days":90}'
cache-control: no-store
{"agent":"support-bot","prefix":"636145edb614","label":"prod","status":"active","created_at":"2026-10-20T10:06:49Z","expires_at":"2027-01-18T10:06:49Z","revoked_at":null,"last_used_at":null,"key":"mcpw_636145edb…"}

$ tools/call echo {"text": "hello"} (twice, with the new key)
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}],"isError":false}} [HTTP 200]
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}],"isError":false}} [HTTP 200]

$ curl localhost:8080/v1/usage -H "authorization: Bearer $ALICE_TOKEN"
{"usage":[{"budget":"demo-echo","agent":"support-bot","server":"demo","tool":"echo","window_start":"2026-10-20T10:00:00Z","window_end":"2026-10-20T11:00:00Z","calls":2,"tokens":52,"max_calls":50,"max_tokens":5000},{"budget":"daily-calls","agent":"support-bot","server":null,"tool":null,"window_start":"2026-10-20T00:00:00Z","window_end":"2026-10-21T00:00:00Z","calls":2,"tokens":52,"max_calls":2000,"max_tokens":null},{"budget":"support-bot-tokens","agent":"support-bot","server":null,"tool":null,"window_start":"2026-10-20T00:00:00Z","window_end":"2026-10-21T00:00:00Z","calls":2,"tokens":52,"max_calls":null,"max_tokens":200000}]}
```

During an incident Bob adds a rule denying `echo` to the file and reloads it from the
CLI (`WARDEN_ADMIN_TOKEN` holds his token). `policy show` still reports the version in
force until the reload:

```text
$ mcp-warden policy show
version 1, default deny, 9 rules, 3 rate limits, 3 budgets
source policy.yaml (aac81c906083, loaded 2026-10-20T10:06:26Z)
$ mcp-warden policy reload   # after adding rule echo-off-during-incident
reloaded 1a932150d0f2
  rules added: echo-off-during-incident
```

A later edit has a typo. The reload is refused, the previous policy stays in force and
the failure is visible to anyone who looks. Alice then revokes a second key she had
issued (`demo-2`):

```text
$ tools/call echo {"text": "hello"}
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"tool call denied by policy: echo","data":{"server":"demo","tool":"echo","effect":"deny","rule_id":"echo-off-during-incident","reason":"Echo is switched off while INC-42 is investigated."}}} [HTTP 200]
$ mcp-warden policy reload   # after a typo: effect: block
error: 422: invalid policy: rules.5.effect: Input should be 'allow', 'require_approval' or 'deny'
$ mcp-warden policy show
version 1, default deny, 10 rules, 3 rate limits, 3 budgets
source policy.yaml (1a932150d0f2, loaded 2026-10-20T10:07:01Z)
last reload failed: invalid policy: rules.5.effect: Input should be 'allow', 'require_approval' or 'deny'
$ tools/call echo {"text": "hello"}
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"tool call denied by policy: echo","data":{"server":"demo","tool":"echo","effect":"deny","rule_id":"echo-off-during-incident","reason":"Echo is switched off while INC-42 is investigated."}}} [HTTP 200]
$ curl -X POST localhost:8080/v1/keys/14244387657f/revoke -H "authorization: Bearer $ALICE_TOKEN"
{"agent":"support-bot","prefix":"14244387657f","label":"demo-2","status":"revoked","created_at":"2026-10-20T10:07:19Z","expires_at":null,"revoked_at":"2026-10-20T10:07:21Z","last_used_at":"2026-10-20T10:07:19Z"}
$ initialize with the revoked key
{"jsonrpc":"2.0","id":null,"error":{"code":-32008,"message":"invalid, expired or revoked API key"}} [HTTP 401]
$ curl localhost:8080/v1/agents/support-bot -H "authorization: Bearer $ALICE_TOKEN"
{"name":"support-bot","description":"Tier 1 support","disabled":false,"created_at":"2026-10-20T10:06:49Z","keys":[{"agent":"support-bot","prefix":"636145edb614","label":"prod","status":"active","created_at":"2026-10-20T10:06:49Z","expires_at":"2027-01-18T10:06:49Z","revoked_at":null,"last_used_at":"2026-10-20T10:06:49Z"},{"agent":"support-bot","prefix":"14244387657f","label":"demo-2","status":"revoked","created_at":"2026-10-20T10:07:19Z","expires_at":null,"revoked_at":"2026-10-20T10:07:21Z","last_used_at":"2026-10-20T10:07:19Z"}]}
```

The fake upstream logged six requests: four `initialize` calls and the two allowed
`echo` calls. Neither denied call reached it.

Dry-run a call with arguments without any upstream:

```bash
uv run mcp-warden check examples/policy.yaml \
  --agent bot --server demo --tool sleep --arguments '{"seconds": 30}'
```

Configuration is read from `WARDEN_*` environment variables (`WARDEN_POLICY_PATH`,
`WARDEN_UPSTREAMS_PATH`, `WARDEN_DATABASE_URL`, `WARDEN_AUTH_MODE` (`api-key` or
`trusted-header`), `WARDEN_RATE_LIMIT_STORE` and `WARDEN_USAGE_STORE` (`memory` or
`database`), `WARDEN_CHARS_PER_TOKEN`, the approval settings `WARDEN_APPROVAL_STORE`
(`memory` or `database`), `WARDEN_APPROVAL_TTL_SECONDS`,
`WARDEN_APPROVAL_DECISION_TTL_SECONDS`, `WARDEN_APPROVAL_WAIT_SECONDS`,
`WARDEN_APPROVAL_MAX_PENDING_PER_AGENT` and `WARDEN_APPROVAL_RETRY_AFTER_SECONDS`, the
admin tokens `WARDEN_ADMIN_TOKENS` (named, as JSON) and `WARDEN_ADMIN_TOKEN` (shared),
`WARDEN_POLICY_RELOAD_INTERVAL_SECONDS`, the audit settings `WARDEN_AUDIT_STORE` (`memory`, `database` or
`off`), `WARDEN_AUDIT_HASH_KEY` and `WARDEN_AUDIT_MEMORY_MAX_EVENTS`, the retention
settings `WARDEN_RETENTION_DAYS` and `WARDEN_RETENTION_INTERVAL_SECONDS`, `WARDEN_HOST`, `WARDEN_PORT`, `WARDEN_LOG_LEVEL`,
`WARDEN_LOG_FORMAT` (`text` or `json`), the metrics settings `WARDEN_METRICS_ENABLED`,
`WARDEN_METRICS_TOKEN` and `WARDEN_METRICS_MAX_LABEL_VALUES`, the tracing settings
`WARDEN_TRACING` (`off`, `console` or `otlp`), `WARDEN_OTLP_ENDPOINT`,
`WARDEN_SERVICE_NAME` and `WARDEN_TRACE_SAMPLE_RATIO`, the parser
limits `WARDEN_MAX_MESSAGE_BYTES`, `WARDEN_MAX_JSON_DEPTH`, `WARDEN_MAX_BATCH_SIZE`, and
`WARDEN_MAX_UPSTREAM_RESPONSE_BYTES`).

## Development

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest --cov=mcp_warden

# New migration after changing the models (uses WARDEN_DATABASE_URL)
uv run mcp-warden db upgrade && uv run alembic revision --autogenerate -m "describe change"
```

A test compares the migrated schema with the SQLAlchemy models, so a model change
without a migration fails CI.

The database tests run on SQLite by default. Point `WARDEN_TEST_POSTGRES_URL` at a
throwaway PostgreSQL database (e.g.
`postgresql+psycopg://warden:warden@localhost:5432/warden_test`, after
`uv sync --extra postgres`) to also run them against PostgreSQL, including the
concurrency tests for shared rate limits, budgets and approvals, and the audit store
and retention tests.

CI runs the same lint, type-check, test and build steps on every push, with a
PostgreSQL 16 service so the PostgreSQL variants run too. A second job lints the
Dockerfile with hadolint, builds the image, checks that it runs as a non-root user,
starts the Compose stack and runs the demo agent against it twice.

The tests never read a `.env` in the working directory (the one Compose uses), so local
secrets cannot change their results.

## License

[MIT](LICENSE)
