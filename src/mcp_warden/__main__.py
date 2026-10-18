"""Command-line entry point.

``serve``, ``check`` and ``fake-upstream`` run the gateway and its tools;
``db``, ``agents`` and ``keys`` manage the identity database; ``usage``
reports the budget usage ledger; ``approvals`` lists and decides tool calls
waiting for a human.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_warden.approval import ApprovalStatus, ApprovalTimings
from mcp_warden.config import Settings
from mcp_warden.db import DatabaseNotReadyError
from mcp_warden.identity import IdentityError, IdentityStore
from mcp_warden.policy import PolicyEngine, PolicyError, ToolCallRequest, load_policy_file
from mcp_warden.upstreams import UpstreamError

if TYPE_CHECKING:
    from mcp_warden.approval import DatabaseApprovalStore


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy_file(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"ok: {args.policy} (version {policy.version}, {len(policy.rules)} rules, "
        f"{len(policy.rate_limits)} rate limits, {len(policy.budgets)} budgets, "
        f"default {policy.default.value})"
    )
    if args.agent and args.server and args.tool:
        arguments = None
        if args.arguments is not None:
            try:
                arguments = json.loads(args.arguments)
            except json.JSONDecodeError as exc:
                print(f"error: --arguments is not valid JSON: {exc}", file=sys.stderr)
                return 2
            if not isinstance(arguments, dict):
                print("error: --arguments must be a JSON object", file=sys.stderr)
                return 2
        decision = PolicyEngine(policy).evaluate(
            ToolCallRequest(args.agent, args.server, args.tool, arguments)
        )
        rule = decision.rule_id or "<default>"
        print(
            f"{decision.effect.value}: {args.agent} -> {args.server}/{args.tool} "
            f"(rule {rule}: {decision.reason})"
        )
        for limit in PolicyEngine(policy).rate_limits_for(args.agent, args.server, args.tool):
            print(
                f"rate limit {limit.id}: {limit.requests}/{limit.per.value}, "
                f"burst {limit.capacity}, per {limit.scope.value}"
            )
        for budget in PolicyEngine(policy).budgets_for(args.agent, args.server, args.tool):
            caps = [
                f"{value} {name}"
                for name, value in (("calls", budget.max_calls), ("tokens", budget.max_tokens))
                if value is not None
            ]
            print(
                f"budget {budget.id}: {', '.join(caps)} per {budget.window.value}, "
                f"per {budget.scope.value}"
            )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from mcp_warden.app import create_app

    overrides: dict[str, object] = {}
    if args.policy:
        overrides["policy_path"] = args.policy
    if args.upstreams:
        overrides["upstreams_path"] = args.upstreams
    settings = Settings(**overrides)  # type: ignore[arg-type]
    try:
        app = create_app(settings)
    except (PolicyError, UpstreamError, DatabaseNotReadyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)
    return 0


def _cmd_fake_upstream(args: argparse.Namespace) -> int:
    import uvicorn

    from mcp_warden.fake_upstream import create_fake_upstream

    app = create_fake_upstream(sse=args.sse)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _database_url(args: argparse.Namespace) -> str:
    url: str = args.database_url or Settings().database_url
    return url


def _cmd_db_upgrade(args: argparse.Namespace) -> int:
    from mcp_warden.db import make_engine, upgrade
    from mcp_warden.db.migrate import current_revision

    engine = make_engine(_database_url(args))
    try:
        upgrade(engine)
        print(f"database at revision {current_revision(engine)}")
    finally:
        engine.dispose()
    return 0


def _with_store(args: argparse.Namespace, action: str) -> int:
    from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker

    engine = make_engine(_database_url(args))
    try:
        ensure_schema_current(engine)
        store = IdentityStore(make_sessionmaker(engine))
        return _IDENTITY_ACTIONS[action](store, args)
    except (DatabaseNotReadyError, IdentityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()


def _cmd_usage(args: argparse.Namespace) -> int:
    from mcp_warden.budget import DatabaseUsageStore
    from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker

    engine = make_engine(_database_url(args))
    try:
        ensure_schema_current(engine)
        records = DatabaseUsageStore(make_sessionmaker(engine)).records(
            agent=args.agent, current_only=not args.all, limit=args.limit
        )
    except DatabaseNotReadyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print("budget\tagent\tserver/tool\twindow\tcalls\ttokens")
    for r in records:
        target = f"{r.server}/{r.tool}" if r.server is not None else "*"
        print(
            f"{r.budget_id}\t{r.agent}\t{target}\t{_fmt(r.window_start)}..{_fmt(r.window_end)}"
            f"\t{r.calls}\t{r.tokens}"
        )
    return 0


def _cmd_approvals(args: argparse.Namespace) -> int:
    from mcp_warden.approval import ApprovalError, DatabaseApprovalStore
    from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker

    engine = make_engine(_database_url(args))
    try:
        ensure_schema_current(engine)
        store = DatabaseApprovalStore(make_sessionmaker(engine))
        return _APPROVAL_ACTIONS[args.approvals_command](store, args)
    except (DatabaseNotReadyError, ApprovalError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()


def _approvals_list(store: DatabaseApprovalStore, args: argparse.Namespace) -> int:
    now = datetime.now(UTC)
    status = None if args.status == "all" else ApprovalStatus(args.status)
    print("id\tstatus\tagent\tserver/tool\trule\tcreated\texpires")
    for r in store.list(now, status=status, agent=args.agent, limit=args.limit):
        print(
            f"{r.id}\t{r.state(now).value}\t{r.agent}\t{r.server}/{r.tool}\t{r.rule_id or '-'}"
            f"\t{_fmt(r.created_at)}\t{_fmt(r.expires_at)}"
        )
    return 0


def _approvals_show(store: DatabaseApprovalStore, args: argparse.Namespace) -> int:
    request = store.get(args.id)
    print(json.dumps(request.to_dict(datetime.now(UTC)), indent=2, sort_keys=True))
    return 0


def _approvals_decide(store: DatabaseApprovalStore, args: argparse.Namespace) -> int:
    approve = args.approvals_command == "approve"
    settings = Settings()
    timings = ApprovalTimings(
        pending_ttl=timedelta(seconds=settings.approval_ttl_seconds),
        decision_ttl=timedelta(seconds=settings.approval_decision_ttl_seconds),
    )
    request = store.decide(
        args.id,
        approve=approve,
        reviewer=args.reviewer,
        note=args.note,
        now=datetime.now(UTC),
        timings=timings,
    )
    verb = "approved" if approve else "denied"
    print(
        f"{verb} {request.id}: {request.agent} -> {request.server}/{request.tool} "
        f"(valid until {_fmt(request.expires_at)})"
    )
    return 0


_APPROVAL_ACTIONS = {
    "list": _approvals_list,
    "show": _approvals_show,
    "approve": _approvals_decide,
    "deny": _approvals_decide,
}


def _default_reviewer() -> str:
    try:
        name = getpass.getuser()
    except (KeyError, OSError):
        return "cli"
    return name if re.fullmatch(r"[A-Za-z0-9_.:@ -]{1,100}", name) else "cli"


def _reviewer(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:@ -]{1,100}", value):
        raise argparse.ArgumentTypeError("1-100 letters, digits, spaces or _.:@-")
    return value


def _note(value: str) -> str:
    if len(value) > 500:
        raise argparse.ArgumentTypeError("at most 500 characters")
    return value


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts is not None else "-"


def _agents_create(store: IdentityStore, args: argparse.Namespace) -> int:
    agent = store.create_agent(args.name, args.description)
    print(f"created agent {agent.name}")
    return 0


def _agents_list(store: IdentityStore, args: argparse.Namespace) -> int:
    for agent in store.list_agents():
        state = "disabled" if agent.disabled else "enabled"
        print(f"{agent.name}\t{state}\t{_fmt(agent.created_at)}\t{agent.description}")
    return 0


def _agents_disable(store: IdentityStore, args: argparse.Namespace) -> int:
    store.set_disabled(args.name, True)
    print(f"disabled agent {args.name}; its keys stop working immediately")
    return 0


def _agents_enable(store: IdentityStore, args: argparse.Namespace) -> int:
    store.set_disabled(args.name, False)
    print(f"enabled agent {args.name}")
    return 0


def _keys_issue(store: IdentityStore, args: argparse.Namespace) -> int:
    expires_in = timedelta(days=args.expires_in_days) if args.expires_in_days else None
    issued = store.issue_key(args.agent, args.label, expires_in)
    print(issued.plaintext)
    print(
        f"issued key {issued.info.prefix} for {issued.info.agent} "
        f"(expires {_fmt(issued.info.expires_at)}). It is shown only once; store it now.",
        file=sys.stderr,
    )
    return 0


def _keys_list(store: IdentityStore, args: argparse.Namespace) -> int:
    now = datetime.now().astimezone()
    for key in store.list_keys(args.agent):
        print(
            f"{key.prefix}\t{key.status(now)}\tcreated {_fmt(key.created_at)}\t"
            f"expires {_fmt(key.expires_at)}\tlast used {_fmt(key.last_used_at)}\t{key.label}"
        )
    return 0


def _keys_revoke(store: IdentityStore, args: argparse.Namespace) -> int:
    key = store.revoke_key(args.prefix)
    print(f"revoked key {key.prefix} of {key.agent} at {_fmt(key.revoked_at)}")
    return 0


_IDENTITY_ACTIONS = {
    "agents-create": _agents_create,
    "agents-list": _agents_list,
    "agents-disable": _agents_disable,
    "agents-enable": _agents_enable,
    "keys-issue": _keys_issue,
    "keys-list": _keys_list,
    "keys-revoke": _keys_revoke,
}


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _add_identity_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    db_url = argparse.ArgumentParser(add_help=False)
    db_url.add_argument(
        "--database-url", help="SQLAlchemy URL (default: WARDEN_DATABASE_URL or local SQLite)"
    )

    def identity(parser: argparse.ArgumentParser, action: str) -> None:
        parser.set_defaults(func=lambda args: _with_store(args, action))

    db = sub.add_parser("db", help="manage the database schema")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser(
        "upgrade", parents=[db_url], help="apply migrations up to the latest revision"
    ).set_defaults(func=_cmd_db_upgrade)

    agents = sub.add_parser("agents", help="manage agents")
    agents_sub = agents.add_subparsers(dest="agents_command", required=True)
    create = agents_sub.add_parser("create", parents=[db_url], help="register an agent")
    create.add_argument("name")
    create.add_argument("--description", default="")
    identity(create, "agents-create")
    identity(agents_sub.add_parser("list", parents=[db_url], help="list agents"), "agents-list")
    for verb in ("disable", "enable"):
        p = agents_sub.add_parser(verb, parents=[db_url], help=f"{verb} an agent")
        p.add_argument("name")
        identity(p, f"agents-{verb}")

    keys = sub.add_parser("keys", help="manage agent API keys")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    issue = keys_sub.add_parser("issue", parents=[db_url], help="issue a key for an agent")
    issue.add_argument("agent")
    issue.add_argument("--label", default="")
    issue.add_argument("--expires-in-days", type=_positive_int, default=None)
    identity(issue, "keys-issue")
    listing = keys_sub.add_parser("list", parents=[db_url], help="list an agent's keys")
    listing.add_argument("agent")
    identity(listing, "keys-list")
    revoke = keys_sub.add_parser("revoke", parents=[db_url], help="revoke a key by prefix")
    revoke.add_argument("prefix")
    identity(revoke, "keys-revoke")

    usage = sub.add_parser(
        "usage", parents=[db_url], help="show budget usage from the database ledger"
    )
    usage.add_argument("--agent", help="only this agent")
    usage.add_argument("--all", action="store_true", help="include windows that have ended")
    usage.add_argument("--limit", type=_positive_int, default=100)
    usage.set_defaults(func=_cmd_usage)

    approvals = sub.add_parser(
        "approvals", help="review tool calls waiting for human approval (database store)"
    )
    approvals_sub = approvals.add_subparsers(dest="approvals_command", required=True)
    alist = approvals_sub.add_parser("list", parents=[db_url], help="list approval requests")
    alist.add_argument(
        "--status",
        choices=[*(s.value for s in ApprovalStatus), "all"],
        default="pending",
        help="filter by status (default: pending, i.e. the review queue)",
    )
    alist.add_argument("--agent", help="only this agent")
    alist.add_argument("--limit", type=_positive_int, default=100)
    show = approvals_sub.add_parser(
        "show", parents=[db_url], help="show one request, including its arguments"
    )
    show.add_argument("id")
    for verb in ("approve", "deny"):
        p = approvals_sub.add_parser(verb, parents=[db_url], help=f"{verb} a pending request")
        p.add_argument("id")
        p.add_argument(
            "--reviewer", type=_reviewer, default=_default_reviewer(), help="who decided"
        )
        p.add_argument("--note", type=_note, default=None, help="reason shown to the agent")
    for p in (alist, show, *(approvals_sub.choices[v] for v in ("approve", "deny"))):
        p.set_defaults(func=_cmd_approvals)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-warden", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a policy file and optionally dry-run a call")
    check.add_argument("policy", type=Path)
    check.add_argument("--agent")
    check.add_argument("--server")
    check.add_argument("--tool")
    check.add_argument(
        "--arguments", help="tool arguments as a JSON object, for rules with argument matchers"
    )
    check.set_defaults(func=_cmd_check)

    serve = sub.add_parser("serve", help="run the gateway HTTP server")
    serve.add_argument("--policy", type=Path, default=None)
    serve.add_argument("--upstreams", type=Path, default=None)
    serve.set_defaults(func=_cmd_serve)

    fake = sub.add_parser(
        "fake-upstream", help="run the deterministic fake MCP server used for demos and tests"
    )
    fake.add_argument("--host", default="127.0.0.1")
    fake.add_argument("--port", type=int, default=9001)
    fake.add_argument("--sse", action="store_true", help="answer with text/event-stream")
    fake.set_defaults(func=_cmd_fake_upstream)

    _add_identity_commands(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
