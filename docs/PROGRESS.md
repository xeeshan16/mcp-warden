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
