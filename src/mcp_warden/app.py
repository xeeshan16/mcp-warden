"""HTTP application factory."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from opentelemetry.trace import TracerProvider
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_warden import __version__
from mcp_warden.admin import AdminPrincipal
from mcp_warden.admin.deps import Admin, AdminDep
from mcp_warden.admin.routes import router as admin_router
from mcp_warden.approval import (
    ApprovalConflictError,
    ApprovalGate,
    ApprovalNotFoundError,
    ApprovalStatus,
    ApprovalStore,
    ApprovalTimings,
    DatabaseApprovalStore,
    InMemoryApprovalStore,
)
from mcp_warden.audit import (
    ArgumentHasher,
    AuditQuery,
    AuditRecorder,
    AuditStore,
    Cursor,
    DatabaseAuditStore,
    InMemoryAuditStore,
    InvalidCursorError,
    Outcome,
)
from mcp_warden.budget import (
    BudgetEnforcer,
    CharRatioEstimator,
    DatabaseUsageStore,
    InMemoryUsageStore,
    TokenEstimator,
    UsageStore,
)
from mcp_warden.config import (
    ApprovalStoreKind,
    AuditStoreKind,
    AuthMode,
    RateLimitStore,
    Settings,
    UsageStoreKind,
)
from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker
from mcp_warden.identity import (
    ApiKeyAuthenticator,
    Authenticator,
    IdentityStore,
    TrustedHeaderAuthenticator,
)
from mcp_warden.jsonrpc import ErrorCode, error_response, to_wire
from mcp_warden.observability.metrics import CONTENT_TYPE, GatewayMetrics
from mcp_warden.observability.tracing import (
    build_tracer_provider,
    shutdown_provider,
    tracer_from,
)
from mcp_warden.policy import PolicyEngine, PolicyError, PolicyReloader, ToolCallRequest
from mcp_warden.proxy import (
    HttpUpstreamClient,
    InstrumentedTransport,
    PolicyGuard,
    ProxyResult,
    ProxyService,
    UpstreamTransport,
)
from mcp_warden.ratelimit import (
    BucketStore,
    DatabaseBucketStore,
    InMemoryBucketStore,
    RateLimiter,
)
from mcp_warden.retention import RetentionJob
from mcp_warden.upstreams import UpstreamRegistry, load_upstreams_file

logger = logging.getLogger(__name__)

_NAME = r"^[A-Za-z0-9_.:/-]{1,200}$"


class EvaluateRequest(BaseModel):
    agent: str = Field(pattern=_NAME)
    server: str = Field(pattern=_NAME)
    tool: str = Field(pattern=_NAME)
    arguments: dict[str, Any] | None = Field(
        default=None, description="Tool arguments, for rules with argument matchers."
    )


class EvaluateResponse(BaseModel):
    effect: str
    rule_id: str | None
    reason: str
    matched_rule_ids: list[str]


class PolicySource(BaseModel):
    path: str
    sha256: str | None
    loaded_at: str | None
    last_checked_at: str | None
    last_error: str | None = Field(description="Why the last reload failed, if it did.")
    reloads: int
    failed_reloads: int


class PolicySummary(BaseModel):
    version: int
    default: str
    rule_count: int
    rule_ids: list[str]
    rate_limit_ids: list[str]
    budget_ids: list[str]
    source: PolicySource


def _summary(engine: PolicyEngine, reloader: PolicyReloader) -> PolicySummary:
    policy = engine.policy
    return PolicySummary(
        version=policy.version,
        default=policy.default.value,
        rule_count=len(policy.rules),
        rule_ids=[r.id for r in policy.rules],
        rate_limit_ids=[r.id for r in policy.rate_limits],
        budget_ids=[b.id for b in policy.budgets],
        source=PolicySource(**reloader.status()),
    )


class ReviewDecision(BaseModel):
    reviewer: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_.:@ -]{1,100}$",
        description="Who decided. Taken from a named admin token; needed with the shared one.",
    )
    note: str | None = Field(default=None, max_length=500)


def get_engine(request: Request) -> PolicyEngine:
    engine: PolicyEngine = request.app.state.engine
    return engine


EngineDep = Annotated[PolicyEngine, Depends(get_engine)]


def get_proxy(request: Request) -> ProxyService:
    proxy: ProxyService = request.app.state.proxy
    return proxy


ProxyDep = Annotated[ProxyService, Depends(get_proxy)]


def get_gate(request: Request) -> ApprovalGate:
    gate: ApprovalGate = request.app.state.approvals
    return gate


GateDep = Annotated[ApprovalGate, Depends(get_gate)]


def get_audit_store(request: Request) -> AuditStore:
    store: AuditStore | None = request.app.state.audit_store
    if store is None:
        raise HTTPException(404, "audit log disabled: WARDEN_AUDIT_STORE=off")
    return store


AuditDep = Annotated[AuditStore, Depends(get_audit_store)]
QueryName = Annotated[str | None, Query(max_length=200)]


ApprovalId = Annotated[str, Path(max_length=64)]


def _reviewer(body: ReviewDecision, admin: AdminPrincipal) -> str:
    """Named admins decide as themselves; the shared token names the reviewer."""
    if admin.shared:
        return body.reviewer or admin.name
    if body.reviewer is not None and body.reviewer != admin.name:
        raise HTTPException(403, f"{admin.name} cannot decide as {body.reviewer}")
    return admin.name


class _BodyTooLargeError(Exception):
    pass


async def _read_body(request: Request, max_bytes: int) -> bytes:
    """Read the request body, refusing to buffer more than ``max_bytes``."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise _BodyTooLargeError
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise _BodyTooLargeError
    return bytes(buf)


def _http_response(result: ProxyResult) -> Response:
    if result.body is None:
        return Response(status_code=result.status, headers=dict(result.headers))
    return JSONResponse(result.body, status_code=result.status, headers=dict(result.headers))


def _jsonrpc_http_error(status: int, code: ErrorCode, message: str) -> Response:
    return JSONResponse(to_wire(error_response(None, code, message)), status_code=status)


class _HttpMetricsMiddleware:
    """Counts every HTTP request by route template (bounded), method and status."""

    def __init__(self, app: ASGIApp, metrics: GatewayMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            # The template, never the raw path, so ids in paths do not become labels.
            template = getattr(route, "path", None) or "unmatched"
            self.metrics.observe_http(
                template, scope["method"], status, time.perf_counter() - started
            )


def _metrics_authorized(request: Request, token: str | None) -> bool:
    if token is None:
        return True
    header = request.headers.get("authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return False
    return hmac.compare_digest(
        hashlib.sha256(supplied.strip().encode()).digest(),
        hashlib.sha256(token.encode()).digest(),
    )


def create_app(
    settings: Settings | None = None,
    engine: PolicyEngine | None = None,
    upstreams: UpstreamRegistry | None = None,
    transport: UpstreamTransport | None = None,
    authenticator: Authenticator | None = None,
    bucket_store: BucketStore | None = None,
    usage_store: UsageStore | None = None,
    token_estimator: TokenEstimator | None = None,
    budget_clock: Callable[[], datetime] | None = None,
    approval_store: ApprovalStore | None = None,
    approval_gate: ApprovalGate | None = None,
    audit_store: AuditStore | None = None,
    audit_clock: Callable[[], datetime] | None = None,
    metrics: GatewayMetrics | None = None,
    tracer_provider: TracerProvider | None = None,
) -> FastAPI:
    """Build the FastAPI app.

    The policy, the upstream registry and (in API key mode) the database
    schema are checked eagerly so that a broken file, a missing upstream
    credential or a forgotten migration stops startup instead of surfacing on
    the first request.

    ``tracer_provider`` overrides ``WARDEN_TRACING``; a provider passed in is
    the caller's to shut down.
    """
    settings = settings or Settings()
    if metrics is None and settings.metrics_enabled:
        metrics = GatewayMetrics(max_label_values=settings.metrics_max_label_values)
    owned_provider = None
    if tracer_provider is None:
        tracer_provider = owned_provider = build_tracer_provider(
            settings.tracing,
            service_name=settings.service_name,
            otlp_endpoint=settings.otlp_endpoint,
            sample_ratio=settings.trace_sample_ratio,
        )
    tracer = tracer_from(tracer_provider)
    if engine is None:
        reloader = PolicyReloader.from_file(settings.policy_path)
        engine = reloader.engine
    else:
        reloader = PolicyReloader(engine, settings.policy_path)
    if upstreams is None:
        upstreams = (
            load_upstreams_file(settings.upstreams_path)
            if settings.upstreams_path is not None
            else UpstreamRegistry()
        )
    transport = InstrumentedTransport(
        transport
        or HttpUpstreamClient(
            max_response_bytes=settings.max_upstream_response_bytes,
            max_json_depth=settings.max_json_depth,
        ),
        metrics=metrics,
        tracer=tracer,
    )
    db_engine = None
    if (
        (authenticator is None and settings.auth_mode is AuthMode.API_KEY)
        or (bucket_store is None and settings.rate_limit_store is RateLimitStore.DATABASE)
        or (usage_store is None and settings.usage_store is UsageStoreKind.DATABASE)
        or (
            approval_gate is None
            and approval_store is None
            and settings.approval_store is ApprovalStoreKind.DATABASE
        )
        or (audit_store is None and settings.audit_store is AuditStoreKind.DATABASE)
    ):
        db_engine = make_engine(settings.database_url)
        try:
            ensure_schema_current(db_engine)
        except Exception:
            db_engine.dispose()
            raise
    identity = None
    if settings.auth_mode is AuthMode.API_KEY and db_engine is not None:
        identity = IdentityStore(make_sessionmaker(db_engine))
    if authenticator is None:
        if identity is None:
            logger.warning(
                "auth mode %s: agent identity is taken from X-Warden-Agent unchecked",
                settings.auth_mode.value,
            )
            authenticator = TrustedHeaderAuthenticator()
        else:
            authenticator = ApiKeyAuthenticator(identity)
    if bucket_store is None:
        if settings.rate_limit_store is RateLimitStore.DATABASE and db_engine is not None:
            bucket_store = DatabaseBucketStore(make_sessionmaker(db_engine))
        else:
            bucket_store = InMemoryBucketStore()
    if usage_store is None:
        if settings.usage_store is UsageStoreKind.DATABASE and db_engine is not None:
            usage_store = DatabaseUsageStore(make_sessionmaker(db_engine))
        else:
            usage_store = InMemoryUsageStore()
    if approval_gate is None:
        if approval_store is None:
            if settings.approval_store is ApprovalStoreKind.DATABASE and db_engine is not None:
                approval_store = DatabaseApprovalStore(make_sessionmaker(db_engine))
            else:
                approval_store = InMemoryApprovalStore()
        approval_gate = ApprovalGate(
            approval_store,
            ApprovalTimings(
                pending_ttl=timedelta(seconds=settings.approval_ttl_seconds),
                decision_ttl=timedelta(seconds=settings.approval_decision_ttl_seconds),
                max_pending_per_agent=settings.approval_max_pending_per_agent,
            ),
            wait=timedelta(seconds=settings.approval_wait_seconds),
            retry_after=settings.approval_retry_after_seconds,
        )
    if audit_store is None:
        if settings.audit_store is AuditStoreKind.DATABASE and db_engine is not None:
            audit_store = DatabaseAuditStore(make_sessionmaker(db_engine))
        elif settings.audit_store is AuditStoreKind.MEMORY:
            audit_store = InMemoryAuditStore(settings.audit_memory_max_events)
    key = settings.audit_hash_key
    # Always built: metrics derive from its events even with the audit log off.
    recorder = AuditRecorder(
        audit_store,
        ArgumentHasher(key.get_secret_value().encode() if key is not None else None),
        clock=audit_clock,
        observers=[metrics.observe_events] if metrics is not None else (),
    )
    if audit_store is not None and key is None:
        logger.warning(
            "audit argument digests are plain SHA-256; set WARDEN_AUDIT_HASH_KEY "
            "so that small arguments cannot be recovered by guessing"
        )
    retention = RetentionJob(
        timedelta(days=settings.retention_days),
        audit=audit_store,
        approvals=approval_gate.store,
        usage=usage_store if isinstance(usage_store, DatabaseUsageStore) else None,
        buckets=bucket_store if isinstance(bucket_store, DatabaseBucketStore) else None,
    )
    budgets = BudgetEnforcer(
        engine,
        usage_store,
        token_estimator or CharRatioEstimator(settings.chars_per_token),
        budget_clock,
        observer=metrics,
    )
    proxy = ProxyService(
        upstreams,
        transport,
        PolicyGuard(engine),
        authenticator,
        settings.parse_limits(),
        RateLimiter(engine, bucket_store),
        budgets,
        approval_gate,
        recorder,
        tracer=tracer,
        metrics=metrics,
    )
    if metrics is not None:
        metrics.track_state(reloader, recorder)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        tasks = []
        if settings.retention_interval_seconds > 0:
            tasks.append(
                asyncio.create_task(retention.run_periodically(settings.retention_interval_seconds))
            )
        if settings.policy_reload_interval_seconds > 0:
            tasks.append(
                asyncio.create_task(
                    reloader.run_periodically(settings.policy_reload_interval_seconds)
                )
            )
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await transport.aclose()
            if db_engine is not None:
                db_engine.dispose()
            shutdown_provider(owned_provider)

    app = FastAPI(title="MCP Warden", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.admins = settings.admin_authenticator()
    app.state.engine = engine
    app.state.policy_reloader = reloader
    app.state.proxy = proxy
    app.state.approvals = approval_gate
    app.state.identity = identity
    app.state.usage_store = usage_store
    app.state.audit_store = audit_store
    app.state.audit = recorder
    app.state.retention = retention
    app.state.metrics = metrics
    app.state.tracer_provider = tracer_provider
    if metrics is not None:
        app.add_middleware(_HttpMetricsMiddleware, metrics=metrics)
        metrics_token = (
            settings.metrics_token.get_secret_value() if settings.metrics_token else None
        )

        @app.get("/metrics", tags=["ops"], include_in_schema=False)
        def prometheus_metrics(request: Request) -> Response:
            """Prometheus text exposition of the gateway's metrics."""
            if not _metrics_authorized(request, metrics_token):
                return Response(status_code=401, headers={"www-authenticate": "Bearer"})
            return Response(metrics.exposition(), media_type=CONTENT_TYPE)

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/policy", response_model=PolicySummary, tags=["policy"], dependencies=[AdminDep])
    def policy_summary(engine: EngineDep) -> PolicySummary:
        """The policy in force and where it came from, including a failed reload."""
        return _summary(engine, reloader)

    @app.post("/v1/policy/reload", tags=["policy"])
    def reload_policy(admin: Admin) -> dict[str, Any]:
        """Re-read the policy file, validate it and swap it in.

        An invalid file is refused with 422 and the current policy stays in force.
        """
        try:
            result = reloader.reload()
        except PolicyError as exc:
            logger.warning("policy reload by %s refused: %s", admin.name, exc)
            raise HTTPException(422, str(exc)) from exc
        if result.changed:
            logger.info("policy reload requested by %s applied", admin.name)
        body = result.to_dict()
        body["policy"] = _summary(reloader.engine, reloader).model_dump()
        return body

    @app.post(
        "/v1/policy/evaluate",
        response_model=EvaluateResponse,
        tags=["policy"],
        dependencies=[AdminDep],
    )
    def evaluate(body: EvaluateRequest, engine: EngineDep) -> EvaluateResponse:
        """Dry-run a decision without calling any upstream server."""
        decision = engine.evaluate(
            ToolCallRequest(body.agent, body.server, body.tool, body.arguments)
        )
        return EvaluateResponse(
            effect=decision.effect.value,
            rule_id=decision.rule_id,
            reason=decision.reason,
            matched_rule_ids=list(decision.matched_rule_ids),
        )

    @app.get("/v1/approvals", tags=["approvals"], dependencies=[AdminDep])
    def list_approvals(
        gate: GateDep,
        status: ApprovalStatus | None = None,
        agent: Annotated[str | None, Query(max_length=200)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """Approval requests, newest first; ``status=pending`` is the review queue."""
        now = gate.now()
        requests = gate.store.list(now, status=status, agent=agent, limit=limit)
        return {"approvals": [r.to_dict(now) for r in requests]}

    @app.get("/v1/approvals/{approval_id}", tags=["approvals"], dependencies=[AdminDep])
    def get_approval(approval_id: ApprovalId, gate: GateDep) -> dict[str, Any]:
        try:
            return gate.store.get(approval_id).to_dict(gate.now())
        except ApprovalNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc

    def _decide(
        gate: ApprovalGate,
        approval_id: str,
        body: ReviewDecision,
        admin: AdminPrincipal,
        approve: bool,
    ) -> Any:
        reviewer = _reviewer(body, admin)
        try:
            request = gate.store.decide(
                approval_id,
                approve=approve,
                reviewer=reviewer,
                note=body.note,
                now=gate.now(),
                timings=gate.timings,
            )
        except ApprovalNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ApprovalConflictError as exc:
            raise HTTPException(409, str(exc)) from exc
        logger.info(
            "approval %s %s by %s",
            request.id,
            "approved" if approve else "denied",
            reviewer,
        )
        return request.to_dict(gate.now())

    @app.post("/v1/approvals/{approval_id}/approve", tags=["approvals"])
    def approve(
        approval_id: ApprovalId, body: ReviewDecision, gate: GateDep, admin: Admin
    ) -> dict[str, Any]:
        """Approve a pending request; the agent's next identical call goes through."""
        result: dict[str, Any] = _decide(gate, approval_id, body, admin, True)
        return result

    @app.post("/v1/approvals/{approval_id}/deny", tags=["approvals"])
    def deny(
        approval_id: ApprovalId, body: ReviewDecision, gate: GateDep, admin: Admin
    ) -> dict[str, Any]:
        """Deny a pending request; repeats of the call are refused while the denial holds."""
        result: dict[str, Any] = _decide(gate, approval_id, body, admin, False)
        return result

    @app.get("/v1/audit", tags=["audit"], dependencies=[AdminDep])
    def list_audit_events(
        store: AuditDep,
        agent: QueryName = None,
        server: QueryName = None,
        tool: QueryName = None,
        method: Annotated[str | None, Query(max_length=100)] = None,
        outcome: Outcome | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        cursor: Annotated[str | None, Query(max_length=300)] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Audit events newest first. Pass ``next_cursor`` back as ``cursor`` for the next page.

        ``since`` is inclusive and ``until`` exclusive; both need a time zone
        (``2026-10-19T09:00:00Z``).
        """
        for name, ts in (("since", since), ("until", until)):
            if ts is not None and ts.tzinfo is None:
                raise HTTPException(422, f"{name} must include a time zone, e.g. Z")
        try:
            query = AuditQuery(
                agent=agent,
                server=server,
                tool=tool,
                method=method,
                outcome=outcome,
                since=since,
                until=until,
                cursor=Cursor.decode(cursor) if cursor is not None else None,
                limit=limit,
            )
        except InvalidCursorError as exc:
            raise HTTPException(400, str(exc)) from exc
        return store.query(query).to_dict()

    app.include_router(admin_router)

    @app.post("/mcp/{server}", tags=["proxy"])
    async def mcp_post(server: str, request: Request, proxy: ProxyDep) -> Response:
        """Streamable HTTP endpoint: forward JSON-RPC to the named upstream."""
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            if metrics is not None:
                metrics.rejected("unsupported_media_type")
            return _jsonrpc_http_error(
                415, ErrorCode.INVALID_REQUEST, "content-type must be application/json"
            )
        limit = proxy.limits.max_bytes
        try:
            body = await _read_body(request, limit)
        except _BodyTooLargeError:
            if metrics is not None:
                metrics.rejected("payload_too_large")
            return _jsonrpc_http_error(413, ErrorCode.PAYLOAD_TOO_LARGE, "payload too large")
        result = await proxy.handle(server, body, request.headers)
        return _http_response(result)

    @app.api_route("/mcp/{server}", methods=["GET", "DELETE"], tags=["proxy"])
    async def mcp_not_supported(server: str) -> Response:
        # Server-initiated SSE streams and explicit session teardown are not
        # proxied yet; MCP lets a server answer both with 405.
        return Response(status_code=405, headers={"allow": "POST"})

    return app
