"""FastAPI dependencies shared by every admin endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from mcp_warden.admin.auth import AdminAuthenticator, AdminPrincipal
from mcp_warden.identity import bearer_token

ADMIN_REALM = 'Bearer realm="mcp-warden-admin"'


def require_admin(request: Request) -> AdminPrincipal:
    """Admin endpoints need ``Authorization: Bearer <admin token>``.

    Without a configured token the admin API is switched off entirely, so a
    gateway is never manageable by anyone who can reach it by default.
    """
    admins: AdminAuthenticator = request.app.state.admins
    if not admins.enabled:
        raise HTTPException(
            503, "admin API disabled: set WARDEN_ADMIN_TOKENS or WARDEN_ADMIN_TOKEN"
        )
    principal = admins.authenticate(bearer_token(request.headers))
    if principal is None:
        raise HTTPException(
            401, "invalid or missing admin token", {"www-authenticate": ADMIN_REALM}
        )
    return principal


AdminDep = Depends(require_admin)
Admin = Annotated[AdminPrincipal, AdminDep]
