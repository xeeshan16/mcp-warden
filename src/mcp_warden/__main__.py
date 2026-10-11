"""Command-line entry point: ``mcp-warden serve`` and ``mcp-warden check``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_warden.config import Settings
from mcp_warden.policy import PolicyEngine, PolicyError, ToolCallRequest, load_policy_file


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy_file(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"ok: {args.policy} (version {policy.version}, {len(policy.rules)} rules, "
        f"default {policy.default.value})"
    )
    if args.agent and args.server and args.tool:
        decision = PolicyEngine(policy).evaluate(
            ToolCallRequest(args.agent, args.server, args.tool)
        )
        rule = decision.rule_id or "<default>"
        print(
            f"{decision.effect.value}: {args.agent} -> {args.server}/{args.tool} "
            f"(rule {rule}: {decision.reason})"
        )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from mcp_warden.app import create_app

    overrides: dict[str, object] = {}
    if args.policy:
        overrides["policy_path"] = args.policy
    settings = Settings(**overrides)  # type: ignore[arg-type]
    try:
        app = create_app(settings)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-warden", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a policy file and optionally dry-run a call")
    check.add_argument("policy", type=Path)
    check.add_argument("--agent")
    check.add_argument("--server")
    check.add_argument("--tool")
    check.set_defaults(func=_cmd_check)

    serve = sub.add_parser("serve", help="run the gateway HTTP server")
    serve.add_argument("--policy", type=Path, default=None)
    serve.set_defaults(func=_cmd_serve)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
