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
