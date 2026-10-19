# MCP Warden

[![CI](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A self-hosted policy, budget and audit gateway for AI agent tool calls over the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP).**

> Status: under active development (day 9 of a 14-day build). See
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
| Prometheus metrics and OpenTelemetry tracing | _planned_ |
| PostgreSQL persistence, Docker Compose demo | _planned_ |

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
approval (day 8) and the audit log with its retention job (day 9) are in place. The full
admin API lands next (see the plan).

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

- the admin API, enabled by setting `WARDEN_ADMIN_TOKEN` (at least 16 characters; the
  API answers `503` while it is unset, and `401` to anything but
  `Authorization: Bearer <token>`, compared in constant time):
  `GET /v1/approvals?status=pending&agent=...`, `GET /v1/approvals/{id}`,
  `POST /v1/approvals/{id}/approve` and `.../deny` with `{"reviewer": "...", "note": "..."}`.
  Deciding a request that is not pending is `409`. Per-reviewer admin identities
  arrive with the admin API on day 10; until then `reviewer` is recorded as given;
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

# Dry-run a decision over HTTP
uv run mcp-warden serve --policy examples/policy.yaml
curl -s localhost:8080/v1/policy/evaluate \
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
`WARDEN_APPROVAL_MAX_PENDING_PER_AGENT`, `WARDEN_APPROVAL_RETRY_AFTER_SECONDS` and
`WARDEN_ADMIN_TOKEN`, the audit settings `WARDEN_AUDIT_STORE` (`memory`, `database` or
`off`), `WARDEN_AUDIT_HASH_KEY` and `WARDEN_AUDIT_MEMORY_MAX_EVENTS`, the retention
settings `WARDEN_RETENTION_DAYS` and `WARDEN_RETENTION_INTERVAL_SECONDS`, `WARDEN_HOST`, `WARDEN_PORT`, `WARDEN_LOG_LEVEL`, the parser
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
PostgreSQL 16 service so the PostgreSQL variants run too.

## License

[MIT](LICENSE)
