"""HTTP application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from mcp_warden import __version__
from mcp_warden.config import Settings
from mcp_warden.jsonrpc import ErrorCode, error_response, to_wire
from mcp_warden.policy import PolicyEngine, ToolCallRequest, load_policy_file
from mcp_warden.proxy import HttpUpstreamClient, ProxyResult, ProxyService, UpstreamTransport
from mcp_warden.upstreams import UpstreamRegistry, load_upstreams_file

_NAME = r"^[A-Za-z0-9_.:/-]{1,200}$"


class EvaluateRequest(BaseModel):
    agent: str = Field(pattern=_NAME)
    server: str = Field(pattern=_NAME)
    tool: str = Field(pattern=_NAME)


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
) -> FastAPI:
    """Build the FastAPI app.

    The policy and the upstream registry are loaded eagerly so that a broken
    file (or a missing upstream credential) stops startup instead of surfacing
    on the first request.
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
    proxy = ProxyService(upstreams, transport, settings.parse_limits())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await transport.aclose()

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
        )

    @app.post("/v1/policy/evaluate", response_model=EvaluateResponse, tags=["policy"])
    def evaluate(body: EvaluateRequest, engine: EngineDep) -> EvaluateResponse:
        """Dry-run a decision without calling any upstream server."""
        decision = engine.evaluate(ToolCallRequest(body.agent, body.server, body.tool))
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
