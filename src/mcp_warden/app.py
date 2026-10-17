"""HTTP application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from mcp_warden import __version__
from mcp_warden.budget import (
    BudgetEnforcer,
    CharRatioEstimator,
    DatabaseUsageStore,
    InMemoryUsageStore,
    TokenEstimator,
    UsageStore,
)
from mcp_warden.config import AuthMode, RateLimitStore, Settings, UsageStoreKind
from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker
from mcp_warden.identity import (
    ApiKeyAuthenticator,
    Authenticator,
    IdentityStore,
    TrustedHeaderAuthenticator,
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


def get_engine(request: Request) -> PolicyEngine:
    engine: PolicyEngine = request.app.state.engine
    return engine


EngineDep = Annotated[PolicyEngine, Depends(get_engine)]


def get_proxy(request: Request) -> ProxyService:
    proxy: ProxyService = request.app.state.proxy
    return proxy


ProxyDep = Annotated[ProxyService, Depends(get_proxy)]


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
