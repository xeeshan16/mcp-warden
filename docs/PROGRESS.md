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
