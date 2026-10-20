"""Admin endpoints for agents, their keys and budget usage.

Everything here needs an admin token (see :mod:`mcp_warden.admin.auth`) and is
logged with the admin's name. The identity endpoints need the identity
database, i.e. ``WARDEN_AUTH_MODE=api-key``; in trusted-header mode there are
no agents to manage and they answer 404.

A key's plaintext is returned exactly once, by the request that issues it,
with ``Cache-Control: no-store``; afterwards only its prefix is known.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, Field

from mcp_warden.admin.deps import Admin
from mcp_warden.budget import UsageRecord
from mcp_warden.identity import (
    AgentExistsError,
    AgentInfo,
    AgentNotFoundError,
    IdentityError,
    IdentityStore,
    KeyInfo,
    KeyNotFoundError,
)
from mcp_warden.policy import PolicyEngine

logger = logging.getLogger(__name__)


class UsageReport(Protocol):
    def records(
        self, *, agent: str | None = None, current_only: bool = True, limit: int = 100
    ) -> list[UsageRecord]: ...


class NewAgent(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.:@-]{1,100}$")
    description: str = Field(default="", max_length=500)


class NewKey(BaseModel):
    label: str = Field(default="", max_length=100)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def _iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts is not None else None


def agent_dict(agent: AgentInfo) -> dict[str, Any]:
    return {
        "name": agent.name,
        "description": agent.description,
        "disabled": agent.disabled,
        "created_at": _iso(agent.created_at),
    }


def key_dict(key: KeyInfo, now: datetime) -> dict[str, Any]:
    return {
        "agent": key.agent,
        "prefix": key.prefix,
        "label": key.label,
        "status": key.status(now),
        "created_at": _iso(key.created_at),
        "expires_at": _iso(key.expires_at),
        "revoked_at": _iso(key.revoked_at),
        "last_used_at": _iso(key.last_used_at),
    }


def usage_dict(record: UsageRecord, engine: PolicyEngine) -> dict[str, Any]:
    budget = next((b for b in engine.policy.budgets if b.id == record.budget_id), None)
    return {
        "budget": record.budget_id,
        "agent": record.agent,
        "server": record.server,
        "tool": record.tool,
        "window_start": _iso(record.window_start),
        "window_end": _iso(record.window_end),
        "calls": record.calls,
        "tokens": record.tokens,
        # Limits as the policy in force states them; null once a budget is removed.
        "max_calls": budget.max_calls if budget is not None else None,
        "max_tokens": budget.max_tokens if budget is not None else None,
    }


def get_identity(request: Request) -> IdentityStore:
    store: IdentityStore | None = request.app.state.identity
    if store is None:
        raise HTTPException(
            404, "agent management needs the identity database: WARDEN_AUTH_MODE=api-key"
        )
    return store


Identity = Annotated[IdentityStore, Depends(get_identity)]
AgentName = Annotated[str, Path(max_length=100)]
KeyPrefix = Annotated[str, Path(max_length=64)]


router = APIRouter(prefix="/v1")


def now() -> datetime:
    return datetime.now(UTC)


def _translate(exc: IdentityError) -> HTTPException:
    if isinstance(exc, AgentExistsError):
        return HTTPException(409, str(exc))
    if isinstance(exc, AgentNotFoundError | KeyNotFoundError):
        return HTTPException(404, str(exc))
    return HTTPException(422, str(exc))


@router.get("/agents", tags=["agents"])
def list_agents(store: Identity, admin: Admin) -> dict[str, Any]:
    return {"agents": [agent_dict(a) for a in store.list_agents()]}


@router.post("/agents", tags=["agents"], status_code=201)
def create_agent(body: NewAgent, store: Identity, admin: Admin) -> dict[str, Any]:
    try:
        agent = store.create_agent(body.name, body.description)
    except IdentityError as exc:
        raise _translate(exc) from exc
    logger.info("admin %s created agent %s", admin.name, agent.name)
    return agent_dict(agent)


@router.get("/agents/{name}", tags=["agents"])
def get_agent(name: AgentName, store: Identity, admin: Admin) -> dict[str, Any]:
    """An agent with all its keys (prefixes and status only)."""
    try:
        agent = store.get_agent(name)
        keys = store.list_keys(name)
    except IdentityError as exc:
        raise _translate(exc) from exc
    at = now()
    return {**agent_dict(agent), "keys": [key_dict(k, at) for k in keys]}


def _set_disabled(store: IdentityStore, name: str, disabled: bool, admin: str) -> Any:
    try:
        agent = store.set_disabled(name, disabled)
    except IdentityError as exc:
        raise _translate(exc) from exc
    logger.info("admin %s %s agent %s", admin, "disabled" if disabled else "enabled", name)
    return agent_dict(agent)


@router.post("/agents/{name}/disable", tags=["agents"])
def disable_agent(name: AgentName, store: Identity, admin: Admin) -> dict[str, Any]:
    """Every key of the agent stops working on its next request."""
    result: dict[str, Any] = _set_disabled(store, name, True, admin.name)
    return result


@router.post("/agents/{name}/enable", tags=["agents"])
def enable_agent(name: AgentName, store: Identity, admin: Admin) -> dict[str, Any]:
    result: dict[str, Any] = _set_disabled(store, name, False, admin.name)
    return result


@router.get("/agents/{name}/keys", tags=["keys"])
def list_keys(name: AgentName, store: Identity, admin: Admin) -> dict[str, Any]:
    try:
        keys = store.list_keys(name)
    except IdentityError as exc:
        raise _translate(exc) from exc
    at = now()
    return {"keys": [key_dict(k, at) for k in keys]}


@router.post("/agents/{name}/keys", tags=["keys"], status_code=201)
def issue_key(
    name: AgentName, body: NewKey, store: Identity, admin: Admin, response: Response
) -> dict[str, Any]:
    """Issue a key. The plaintext ``key`` is in this response only; store it now."""
    expires_in = timedelta(days=body.expires_in_days) if body.expires_in_days else None
    try:
        issued = store.issue_key(name, body.label, expires_in)
    except IdentityError as exc:
        raise _translate(exc) from exc
    response.headers["cache-control"] = "no-store"
    logger.info("admin %s issued key %s for %s", admin.name, issued.info.prefix, name)
    return {**key_dict(issued.info, now()), "key": issued.plaintext}


@router.post("/keys/{prefix}/revoke", tags=["keys"])
def revoke_key(prefix: KeyPrefix, store: Identity, admin: Admin) -> dict[str, Any]:
    """Revoke a key by prefix; revoking twice keeps the first time."""
    try:
        key = store.revoke_key(prefix)
    except IdentityError as exc:
        raise _translate(exc) from exc
    logger.info("admin %s revoked key %s of %s", admin.name, key.prefix, key.agent)
    return key_dict(key, now())


@router.get("/usage", tags=["budgets"])
def usage(
    request: Request,
    admin: Admin,
    agent: Annotated[str | None, Query(max_length=100)] = None,
    all_windows: Annotated[bool, Query(alias="all")] = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    """Budget usage counters, newest window first; ``all=true`` adds ended windows."""
    store: UsageReport = request.app.state.usage_store
    if not callable(getattr(store, "records", None)):
        raise HTTPException(404, "this usage store cannot report usage")
    engine: PolicyEngine = request.app.state.engine
    records = store.records(agent=agent, current_only=not all_windows, limit=limit)
    return {"usage": [usage_dict(r, engine) for r in records]}
