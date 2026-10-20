# MCP Warden: 14-day build plan

**Goal:** a self-hosted, MCP-aware gateway that sits between AI agents and MCP servers
and enforces per-agent identity, policy-as-code, rate limits, budgets and human approval,
with a metadata-only audit log and first-class observability.

**Stack:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic, PostgreSQL
(SQLite for fast unit tests), httpx, Prometheus client, OpenTelemetry, pytest, ruff,
mypy (strict), uv, GitHub Actions, Docker Compose.

**Constraints:** runs locally and in CI with no paid APIs or secrets; any token counting
or external integration sits behind an interface with a deterministic fake; synthetic data
only.

## Architecture sketch

```
agent (MCP client) ──JSON-RPC + key──▶ [auth] → [policy] → [rate limit / budget]
                                         → [approval] → [forward] ──▶ upstream MCP server
                                                  └──────▶ [audit log] → PostgreSQL
                                         metrics/traces ──▶ Prometheus / OTel
```

Each stage is a small, independently tested component behind a protocol; the proxy
composes them as a pipeline so a stage can short-circuit with a JSON-RPC error.

## Milestones (one per day)

| Day | Milestone | Done when |
| --- | --- | --- |
| 1 | Scaffold + policy engine | Package layout, YAML policy model with strict validation, deny-overrides engine, `tools/list` visibility filter, `mcp-warden check` CLI, `/healthz` and `/v1/policy/evaluate`, CI (lint, mypy, tests, build), README, LICENSE |
| 2 | MCP JSON-RPC layer | Typed JSON-RPC 2.0 + MCP message models (`initialize`, `tools/list`, `tools/call`, notifications, batches), error codes, size limits, parser tests |
| 3 | Proxy core | Streamable HTTP endpoint `/mcp/{server}` forwarding to upstream via httpx; upstream registry from config; deterministic fake MCP server for tests; timeouts and upstream error mapping |
| 4 | Policy enforcement in the proxy | `tools/call` checked against policy; `tools/list` responses filtered; argument constraints (per-rule matchers on tool arguments); denial returned as JSON-RPC errors |
| 5 | Agent identity | Per-agent API keys (prefix + SHA-256 hash at rest, constant-time compare), SQLAlchemy models, Alembic migrations, key issue/revoke service |
| 6 | Rate limiting | Token-bucket limiter per agent and per agent+tool, pluggable store (in-memory and PostgreSQL), `Retry-After` semantics, clock injected for tests |
| 7 | Budgets | Call and token budgets per agent per window, `TokenEstimator` interface with a deterministic estimator, usage ledger, budget-exhausted errors |
| 8 | Human approval | `require_approval` calls parked in an approvals table; admin approve/deny API; agent receives pending status or the result after approval; expiry |
| 9 | Audit log | Metadata-only records (agent, server, tool, decision, latency, argument hash and size, never payloads), query API with filters and cursor pagination, retention job |
| 10 | Admin API and CLI | Manage agents, keys, policies (validated hot reload), approvals; admin auth; CLI commands for each |
| 11 | Observability | Prometheus metrics (decisions, latency, upstream errors, budget usage), OpenTelemetry tracing with optional exporter, structured JSON logs |
| 12 | Packaging and demo | Dockerfile, Docker Compose (PostgreSQL, warden, demo MCP server), scripted end-to-end demo with a fake agent |
| 13 | Hardening | PostgreSQL integration tests in CI, property-based JSON-RPC fuzzing (Hypothesis), request size limits, header hygiene, threat model doc |
| 14 | Finish | README polish with real output, "How it works" Mermaid diagrams, clean-clone setup verified, "What I'd do next" |

## Change log

- 2026-10-11: plan written out on day 1 from the approved proposal.
- 2026-10-12: day 2 done as planned. Batches are parsed but will only be accepted for
  sessions on MCP revisions before 2025-06-18, which removed batching.
- 2026-10-13: day 3 done as planned. The optional `GET` server-to-client stream,
  `DELETE` session teardown and relaying of server-to-client messages on a POST's SSE
  stream are answered with `405` or dropped for now; relaying them is picked up on
  day 13 (hardening) if time allows.
- 2026-10-14: day 4 done as planned. Argument constraints are expressed as per-rule
  `arguments` matchers. Only `tools/call` and `tools/list` are policed; `resources/*` and
  `prompts/*` are still forwarded unchecked and are added to day 13 (hardening). Whether
  denial details (rule id and description) are shown to agents may become a setting with
  the admin API on day 10.
- 2026-10-15: day 5 done as planned. The `X-Warden-Agent` placeholder stays available as
  an explicit `trusted-header` auth mode for development and tests; API keys are the
  default. Agents and keys are managed from the CLI for now; the admin HTTP API for them
  is part of day 10. The policy dry-run and summary endpoints are still unauthenticated
  until admin auth lands on day 10.
- 2026-10-16: day 6 done as planned. Rate limits are declared in the policy file
  (`rate_limits`) rather than in separate configuration, so they are reviewed with the
  rules. Only `tools/call` is limited. A PostgreSQL service was added to CI today because
  the shared bucket store needs row-lock tests; day 13 keeps the remaining PostgreSQL
  integration work. Pruning refilled database buckets is a method for now and is wired
  into the retention job on day 9.
- 2026-10-17: day 7 done as planned. Budgets are declared in the policy (`budgets`)
  next to rate limits. Windows are fixed calendar windows in UTC rather than rolling,
  so "per day" means what a reader expects and reset times can be reported. Token
  counts are a deterministic estimate (characters / 4 over canonical JSON); an exact
  tokenizer can be plugged in behind the `TokenEstimator` interface. Budget usage is
  exposed through `mcp-warden usage` for now; the HTTP view arrives with the admin API
  on day 10, and pruning ended windows is wired into the retention job on day 9.
- 2026-10-18: day 8 done as planned. Agents collect a decision by repeating the
  identical call (matched by a fingerprint of agent, server, tool and arguments) rather
  than through a new endpoint, so unmodified MCP clients work; holding the request open
  until a decision is an opt-in setting. Approvals are single-use and expire. The admin
  API for approvals is protected by a single bearer token for now; per-reviewer admin
  identities and the rest of the admin API stay on day 10. Pruning finished approval
  requests is added to the day 9 retention job.
- 2026-10-19: day 9 done as planned. Every request routed to an upstream is audited
  (not only `tools/call`), so sessions and listings are visible too; notifications are
  not. Argument digests are HMAC-SHA-256 when `WARDEN_AUDIT_HASH_KEY` is set, because a
  plain hash of small arguments can be reversed by guessing. Audit writes are fail-open
  (logged and counted); exposing the failure counter as a metric is part of day 11. The
  retention job runs from the CLI or inside the gateway on an interval and also prunes
  finished approval requests, ended budget windows and refilled rate-limit buckets.
- 2026-10-20: day 10 done as planned. Admin identity is a set of named bearer tokens
  from configuration rather than a users table: it gives reviewers their own identity
  without adding a login flow, and roles (read-only vs. admin) are left for later. The
  policy stays a file reviewed in pull requests; the API reloads it (validated, with the
  last good version kept on error) rather than accepting policy uploads, so the file
  remains the source of truth. Policy summary and dry-run endpoints now need an admin.
  The CLI keeps working directly on the database for agents, keys, approvals, usage and
  audit, and talks to the gateway only for what lives in its memory (the policy in
  force). Day 11 adds a metric for failed reloads and audit writes.
