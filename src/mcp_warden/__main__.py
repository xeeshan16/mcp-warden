"""Command-line entry point.

``serve``, ``check`` and ``fake-upstream`` run the gateway and its tools;
``policy`` shows or reloads the policy of a running gateway over its admin API;
``db``, ``agents`` and ``keys`` manage the identity database; ``usage``
reports the budget usage ledger; ``approvals`` lists and decides tool calls
waiting for a human; ``audit`` queries the audit log and ``retention`` prunes
old history.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from mcp_warden.approval import ApprovalStatus, ApprovalTimings
from mcp_warden.audit import Outcome
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
    # Uvicorn configures only its own loggers; without this the gateway's
    # info messages (admin changes, policy reloads) would be dropped.
    logging.basicConfig(format="%(levelname)s:     %(name)s: %(message)s")
    logging.getLogger("mcp_warden").setLevel(settings.log_level.upper())
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)
    return 0


DEFAULT_GATEWAY = "http://127.0.0.1:8080"


def _admin_client(base_url: str, token: str) -> httpx.Client:
    return httpx.Client(
        base_url=base_url, headers={"authorization": f"Bearer {token}"}, timeout=10.0
    )


def _cmd_policy(args: argparse.Namespace) -> int:
    # The token comes from the environment only, so it never shows up in
    # shell history or the process list.
    token = os.environ.get("WARDEN_ADMIN_TOKEN")
    if not token:
        print("error: set WARDEN_ADMIN_TOKEN to an admin token", file=sys.stderr)
        return 2
    base_url = args.gateway or os.environ.get("WARDEN_GATEWAY_URL") or DEFAULT_GATEWAY
    reload = args.policy_command == "reload"
    try:
        with _admin_client(base_url, token) as client:
            resp = client.post("/v1/policy/reload") if reload else client.get("/v1/policy")
    except httpx.HTTPError as exc:
        print(f"error: cannot reach the gateway at {base_url}: {exc}", file=sys.stderr)
        return 1
    try:
        body = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    if resp.status_code != 200:
        print(f"error: {resp.status_code}: {body.get('detail', body)}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(body, indent=2))
        return 0
    if reload:
        if not body["changed"]:
            print(f"unchanged: the file matches the policy in force ({body['sha256'][:12]})")
            return 0
        print(f"reloaded {body['sha256'][:12]}")
        for section in ("rules", "rate_limits", "budgets"):
            for verb, ids in body["changes"][section].items():
                if ids:
                    print(f"  {section.replace('_', ' ')} {verb}: {', '.join(ids)}")
        if body["changes"]["default_changed"]:
            print(f"  default is now {body['policy']['default']}")
        return 0
    source = body["source"]
    print(
        f"version {body['version']}, default {body['default']}, {body['rule_count']} rules, "
        f"{len(body['rate_limit_ids'])} rate limits, {len(body['budget_ids'])} budgets"
    )
    print(
        f"source {source['path']} ({(source['sha256'] or '-')[:12]}, loaded {source['loaded_at']})"
    )
    if source["last_error"]:
        print(f"last reload failed: {source['last_error']}")
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


def _cmd_audit(args: argparse.Namespace) -> int:
    from mcp_warden.audit import AuditQuery, Cursor, DatabaseAuditStore, InvalidCursorError
    from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker

    try:
        query = AuditQuery(
            agent=args.agent,
            server=args.server,
            tool=args.tool,
            method=args.method,
            outcome=Outcome(args.outcome) if args.outcome else None,
            since=args.since,
            until=args.until,
            cursor=Cursor.decode(args.cursor) if args.cursor else None,
            limit=args.limit,
        )
    except InvalidCursorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    engine = make_engine(_database_url(args))
    try:
        ensure_schema_current(engine)
        page = DatabaseAuditStore(make_sessionmaker(engine)).query(query)
    except DatabaseNotReadyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    if args.json:
        print(json.dumps(page.to_dict(), indent=2))
        return 0
    print("time\tagent\tserver/tool\toutcome\trule\tcode\tms\targs")
    for e in page.events:
        target = f"{e.server}/{e.tool}" if e.tool is not None else f"{e.server} {e.method}"
        digest = f"{e.arguments_digest[:12]}..({e.arguments_size}B)" if e.arguments_digest else "-"
        print(
            f"{e.occurred_at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z\t{e.agent}\t{target}"
            f"\t{e.outcome.value}{' (isError)' if e.tool_error else ''}"
            f"\t{e.rule_id or '-'}\t{e.error_code or '-'}"
            f"\t{e.latency_ms:.1f}\t{digest}"
        )
    if page.next_cursor:
        print(f"more: --cursor {page.next_cursor}", file=sys.stderr)
    return 0


def _cmd_retention(args: argparse.Namespace) -> int:
    from mcp_warden.approval import DatabaseApprovalStore
    from mcp_warden.audit import DatabaseAuditStore
    from mcp_warden.budget import DatabaseUsageStore
    from mcp_warden.db import ensure_schema_current, make_engine, make_sessionmaker
    from mcp_warden.ratelimit import DatabaseBucketStore
    from mcp_warden.retention import RetentionJob

    days: float = args.days if args.days is not None else Settings().retention_days
    engine = make_engine(_database_url(args))
    try:
        ensure_schema_current(engine)
        sessions = make_sessionmaker(engine)
        report = RetentionJob(
            timedelta(days=days),
            audit=DatabaseAuditStore(sessions),
            approvals=DatabaseApprovalStore(sessions),
            usage=DatabaseUsageStore(sessions),
            buckets=DatabaseBucketStore(sessions),
        ).run()
    except DatabaseNotReadyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(
        f"removed {report.audit_events} audit events, {report.approval_requests} approval "
        f"requests and {report.usage_counters} usage counters older than "
        f"{_fmt(report.cutoff)}, and {report.rate_limit_buckets} refilled rate-limit buckets"
    )
    return 0


def _aware_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "expected an ISO 8601 time, e.g. 2026-10-19T09:00Z"
        ) from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("include a time zone, e.g. 2026-10-19T09:00Z")
    return parsed.astimezone(UTC)


def _positive_days(value: str) -> float:
    try:
        days = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a number of days") from exc
    if not 0 < days <= 3650:
        raise argparse.ArgumentTypeError("must be more than 0 and at most 3650")
    return days


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

    audit = sub.add_parser(
        "audit", parents=[db_url], help="query the audit log (database store), newest first"
    )
    audit.add_argument("--agent")
    audit.add_argument("--server")
    audit.add_argument("--tool")
    audit.add_argument("--method", help="JSON-RPC method, e.g. tools/call")
    audit.add_argument("--outcome", choices=[o.value for o in Outcome])
    audit.add_argument("--since", type=_aware_datetime, help="inclusive, e.g. 2026-10-19T09:00Z")
    audit.add_argument("--until", type=_aware_datetime, help="exclusive")
    audit.add_argument("--cursor", help="continue from a previous page")
    audit.add_argument("--limit", type=_positive_int, default=50)
    audit.add_argument("--json", action="store_true", help="print the page as JSON")
    audit.set_defaults(func=_cmd_audit)

    retention = sub.add_parser(
        "retention",
        parents=[db_url],
        help="delete old audit events, finished approvals, ended budget windows "
        "and refilled rate-limit buckets",
    )
    retention.add_argument(
        "--days",
        type=_positive_days,
        default=None,
        help="keep this many days (WARDEN_RETENTION_DAYS)",
    )
    retention.set_defaults(func=_cmd_retention)


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

    policy = sub.add_parser(
        "policy", help="show or reload the policy of a running gateway (admin API)"
    )
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    for verb, text in (
        ("show", "show the policy in force and where it was loaded from"),
        ("reload", "re-read the policy file; an invalid file is refused and reported"),
    ):
        p = policy_sub.add_parser(verb, help=text)
        p.add_argument(
            "--gateway", help=f"gateway URL (default: WARDEN_GATEWAY_URL or {DEFAULT_GATEWAY})"
        )
        p.add_argument("--json", action="store_true", help="print the response as JSON")
        p.set_defaults(func=_cmd_policy)

    _add_identity_commands(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
