"""HTTP application factory."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel, Field

from mcp_warden import __version__
from mcp_warden.config import Settings
from mcp_warden.policy import PolicyEngine, ToolCallRequest, load_policy_file

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


def create_app(settings: Settings | None = None, engine: PolicyEngine | None = None) -> FastAPI:
    """Build the FastAPI app.

    The policy is loaded eagerly so that a broken policy file stops startup
    instead of surfacing on the first request.
    """
    settings = settings or Settings()
    engine = engine or PolicyEngine(load_policy_file(settings.policy_path))

    app = FastAPI(title="MCP Warden", version=__version__)
    app.state.settings = settings
    app.state.engine = engine

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

    return app
