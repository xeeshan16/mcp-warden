# MCP Warden

[![CI](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/xeeshan16/mcp-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A self-hosted policy, budget and audit gateway for AI agent tool calls over the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP).**

> Status: under active development (day 7 of a 14-day build). See
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
| Human approval queue for risky tools | _planned_ |
| Metadata-only audit log (no payloads stored) | _planned_ |
| Prometheus metrics and OpenTelemetry tracing | _planned_ |
| PostgreSQL persistence, Docker Compose demo | _planned_ |

## Architecture

```mermaid
flowchart LR
    A[AI agent<br/>MCP client] -- "JSON-RPC + API key" --> W
    subgraph W[MCP Warden]
        direction TB
        AU[Authenticate agent] --> P[Policy engine]
        P --> RL[Rate limits and budgets]
        RL --> AP[Approval queue]
        AP --> AL[Audit log]
    end
    W -- "forward allowed calls" --> S1[MCP server: github]
    W --> S2[MCP server: tickets]
    W -.-> DB[(PostgreSQL)]
    W -.-> M[Prometheus / OTel]
```

So far the policy engine (day 1), the JSON-RPC / MCP message layer (day 2), the proxy
path to upstream servers (day 3), policy enforcement inside the proxy (day 4), agent
authentication with API keys (day 5), rate limits (day 6) and budgets (day 7) are in
place. Approvals and the audit log land over the following days (see the plan).

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
| -32002 | human approval required |
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
- `require_approval` → error `-32002` (parking the call for a human arrives on day 8);
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

Dry-run a call with arguments without any upstream:

```bash
uv run mcp-warden check examples/policy.yaml \
  --agent bot --server demo --tool sleep --arguments '{"seconds": 30}'
```

Configuration is read from `WARDEN_*` environment variables (`WARDEN_POLICY_PATH`,
`WARDEN_UPSTREAMS_PATH`, `WARDEN_DATABASE_URL`, `WARDEN_AUTH_MODE` (`api-key` or
`trusted-header`), `WARDEN_RATE_LIMIT_STORE` and `WARDEN_USAGE_STORE` (`memory` or
`database`), `WARDEN_CHARS_PER_TOKEN`, `WARDEN_HOST`, `WARDEN_PORT`, `WARDEN_LOG_LEVEL`, the parser
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
concurrency tests for shared rate limits and budgets.

CI runs the same lint, type-check, test and build steps on every push, with a
PostgreSQL 16 service so the PostgreSQL variants run too.

## License

[MIT](LICENSE)
