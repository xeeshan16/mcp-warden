"""HTTP application factory."""

from __future__ import annotations

import hmac
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from mcp_warden import __version__
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
    bearer_token,
)
from mcp_warden.jsonrpc import ErrorCode, error_response, to_wire
from mcp_warden.policy import PolicyEngine, ToolCallRequest, load_policy_file
from mcp_warden.proxy import (
    HttpUpstreamClient,
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


class PolicySummary(BaseModel):
    version: int
    default: str
    rule_count: int
    rule_ids: list[str]
    rate_limit_ids: list[str]
    budget_ids: list[str]


class ReviewDecision(BaseModel):
    reviewer: str = Field(pattern=r"^[A-Za-z0-9_.:@ -]{1,100}$", description="Who decided.")
    note: str | None = Field(default=None, max_length=500)


ADMIN_REALM = 'Bearer realm="mcp-warden-admin"'


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


def require_admin(request: Request) -> None:
    """Admin endpoints need ``Authorization: Bearer $WARDEN_ADMIN_TOKEN``.

    Without a configured token the admin API is switched off entirely, so a
    gateway is never reviewable by anyone who can reach it by default.
    """
    settings: Settings = request.app.state.settings
    if settings.admin_token is None:
        raise HTTPException(503, "admin API disabled: set WARDEN_ADMIN_TOKEN")
    supplied = bearer_token(request.headers)
    expected = settings.admin_token.get_secret_value().encode()
    if supplied is None or not hmac.compare_digest(supplied.encode(), expected):
        raise HTTPException(
            401, "invalid or missing admin token", {"www-authenticate": ADMIN_REALM}
        )


AdminDep = Depends(require_admin)
ApprovalId = Annotated[str, Path(max_length=64)]


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
) -> FastAPI:
    """Build the FastAPI app.

    The policy, the upstream registry and (in API key mode) the database
    schema are checked eagerly so that a broken file, a missing upstream
    credential or a forgotten migration stops startup instead of surfacing on
    the first request.
    """
    settings = settings or Settings()
    engine = engine or PolicyEngine(load_policy_file(settings.policy_path))
    if upstreams is None:
        upstreams = (
            load_upstreams_file(settings.upstreams_path)
            if settings.upstreams_path is not None
            else UpstreamRegistry()
        )
    transport = transport or HttpUpstreamClient(
        max_response_bytes=settings.max_upstream_response_bytes,
        max_json_depth=settings.max_json_depth,
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
    ):
        db_engine = make_engine(settings.database_url)
        try:
            ensure_schema_current(db_engine)
        except Exception:
            db_engine.dispose()
            raise
    if authenticator is None:
        if settings.auth_mode is AuthMode.TRUSTED_HEADER or db_engine is None:
            logger.warning(
                "auth mode %s: agent identity is taken from X-Warden-Agent unchecked",
                settings.auth_mode.value,
            )
            authenticator = TrustedHeaderAuthenticator()
        else:
            authenticator = ApiKeyAuthenticator(IdentityStore(make_sessionmaker(db_engine)))
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
    budgets = BudgetEnforcer(
        engine,
        usage_store,
        token_estimator or CharRatioEstimator(settings.chars_per_token),
        budget_clock,
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
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await transport.aclose()
            if db_engine is not None:
                db_engine.dispose()

    app = FastAPI(title="MCP Warden", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.proxy = proxy
    app.state.approvals = approval_gate

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/policy", response_model=PolicySummary, tags=["policy"])
    def policy_summary(engine: EngineDep) -> PolicySummary:
        policy = engine.policy
        return PolicySummary(
            version=policy.version,
            default=policy.default.value,
            rule_count=len(policy.rules),
            rule_ids=[r.id for r in policy.rules],
            rate_limit_ids=[r.id for r in policy.rate_limits],
            budget_ids=[b.id for b in policy.budgets],
        )

    @app.post("/v1/policy/evaluate", response_model=EvaluateResponse, tags=["policy"])
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

    def _decide(gate: ApprovalGate, approval_id: str, body: ReviewDecision, approve: bool) -> Any:
        try:
            request = gate.store.decide(
                approval_id,
                approve=approve,
                reviewer=body.reviewer,
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
            body.reviewer,
        )
        return request.to_dict(gate.now())

    @app.post("/v1/approvals/{approval_id}/approve", tags=["approvals"], dependencies=[AdminDep])
    def approve(approval_id: ApprovalId, body: ReviewDecision, gate: GateDep) -> dict[str, Any]:
        """Approve a pending request; the agent's next identical call goes through."""
        result: dict[str, Any] = _decide(gate, approval_id, body, True)
        return result

    @app.post("/v1/approvals/{approval_id}/deny", tags=["approvals"], dependencies=[AdminDep])
    def deny(approval_id: ApprovalId, body: ReviewDecision, gate: GateDep) -> dict[str, Any]:
        """Deny a pending request; repeats of the call are refused while the denial holds."""
        result: dict[str, Any] = _decide(gate, approval_id, body, False)
        return result

    @app.post("/mcp/{server}", tags=["proxy"])
    async def mcp_post(server: str, request: Request, proxy: ProxyDep) -> Response:
        """Streamable HTTP endpoint: forward JSON-RPC to the named upstream."""
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return _jsonrpc_http_error(
                415, ErrorCode.INVALID_REQUEST, "content-type must be application/json"
            )
        limit = proxy.limits.max_bytes
        try:
            body = await _read_body(request, limit)
        except _BodyTooLargeError:
            return _jsonrpc_http_error(413, ErrorCode.PAYLOAD_TOO_LARGE, "payload too large")
        result = await proxy.handle(server, body, request.headers)
        return _http_response(result)

    @app.api_route("/mcp/{server}", methods=["GET", "DELETE"], tags=["proxy"])
    async def mcp_not_supported(server: str) -> Response:
        # Server-initiated SSE streams and explicit session teardown are not
        # proxied yet; MCP lets a server answer both with 405.
        return Response(status_code=405, headers={"allow": "POST"})

    return app
