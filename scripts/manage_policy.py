"""Manage the durable authorization policy (requires Postgres).

  docker compose up -d
  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas

  uv run python scripts/manage_policy.py seed                  # load config/default_policies.json
  uv run python scripts/manage_policy.py list                  # show role -> permissions
  uv run python scripts/manage_policy.py grant member tool:send
  uv run python scripts/manage_policy.py revoke guest kg:read:personal
  uv run python scripts/manage_policy.py export                # dump current policy as JSON

The Postgres ``atlas_role_permissions`` table is empty (deny-all) until seeded — seeding is explicit
and idempotent. No HTTP admin surface (deferred); this CLI is the management tool for M3.4.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from atlas.orchestration.graph import _pg_pool
from atlas.persistence import PostgresPolicyStore

_DEFAULT_FILE = Path("config/default_policies.json")


def _as_json(policies: dict[str, frozenset[str]]) -> str:
    return json.dumps({role: sorted(perms) for role, perms in sorted(policies.items())}, indent=2)


def _cmd_seed(store: PostgresPolicyStore, args: argparse.Namespace) -> None:
    path = Path(args.file)
    mapping: dict[str, list[str]] = json.loads(path.read_text(encoding="utf-8"))
    granted = 0
    for role, permissions in mapping.items():
        for permission in permissions:
            store.grant(role, permission)
            granted += 1
    print(f"seeded {granted} (role, permission) grants from {path} (idempotent)")


def _cmd_list(store: PostgresPolicyStore, _args: argparse.Namespace) -> None:
    policies = store.list_policies()
    if not policies:
        print("(policy table is empty — deny-all. Run: manage_policy.py seed)")
        return
    for role in sorted(policies):
        print(f"  {role}: {', '.join(sorted(policies[role]))}")


def _cmd_grant(store: PostgresPolicyStore, args: argparse.Namespace) -> None:
    store.grant(args.role, args.permission)
    print(f"granted {args.permission} to {args.role}")


def _cmd_revoke(store: PostgresPolicyStore, args: argparse.Namespace) -> None:
    store.revoke(args.role, args.permission)
    print(f"revoked {args.permission} from {args.role}")


def _cmd_export(store: PostgresPolicyStore, _args: argparse.Namespace) -> None:
    print(_as_json(store.list_policies()))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage atlas role→permission policy (Postgres).")
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser("seed", help="idempotently grant the policies in a JSON file")
    seed.add_argument("--file", default=str(_DEFAULT_FILE), help="role->permissions JSON")
    seed.set_defaults(func=_cmd_seed)

    for name in ("list", "show"):
        lst = sub.add_parser(name, help="print current role->permissions")
        lst.set_defaults(func=_cmd_list)

    grant = sub.add_parser("grant", help="grant a permission to a role")
    grant.add_argument("role")
    grant.add_argument("permission")
    grant.set_defaults(func=_cmd_grant)

    revoke = sub.add_parser("revoke", help="revoke a permission from a role")
    revoke.add_argument("role")
    revoke.add_argument("permission")
    revoke.set_defaults(func=_cmd_revoke)

    export = sub.add_parser("export", help="dump the current policy as JSON")
    export.set_defaults(func=_cmd_export)
    return parser


def main() -> None:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set. Start Postgres and export it, e.g.:")
        print("  docker compose up -d")
        print("  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas")
        sys.exit(0)

    args = _build_parser().parse_args()
    pool = _pg_pool(url)
    try:
        store = PostgresPolicyStore(pool)
        args.func(store, args)
    finally:
        pool.close()
        _pg_pool.cache_clear()


if __name__ == "__main__":
    main()
