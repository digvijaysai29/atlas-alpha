"""Manage per-principal OAuth credentials in the credential vault (M4.3).

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token

uv run python scripts/manage_credentials.py list --org acme --user alice
uv run python scripts/manage_credentials.py revoke --org acme --user alice google
"""

from __future__ import annotations

import argparse
import sys

from atlas.config import get_settings
from atlas.governance.credentials import OAuthProvider
from atlas.governance.rbac import Principal
from atlas.orchestration.graph import make_credential_vault


def _principal(org: str, user: str) -> Principal:
    return Principal(user_id=user, roles=("member",), org_id=org)


def _cmd_list(vault: object, args: argparse.Namespace) -> None:
    principal = _principal(args.org, args.user)
    connected = vault.list_connected(principal)  # type: ignore[attr-defined]
    if not connected:
        print(f"(no connected providers for org={args.org!r} user={args.user!r})")
        return
    for provider in connected:
        print(provider.value)


def _cmd_revoke(vault: object, args: argparse.Namespace) -> None:
    principal = _principal(args.org, args.user)
    provider = OAuthProvider(args.provider.lower())
    vault.delete(principal, provider)  # type: ignore[attr-defined]
    print(f"revoked {provider.value} for org={args.org!r} user={args.user!r}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage atlas OAuth credentials in Vault.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("list", "show"):
        lst = sub.add_parser(name, help="list connected OAuth providers for a principal")
        lst.add_argument("--org", required=True, help="organization id")
        lst.add_argument("--user", required=True, help="user id")
        lst.set_defaults(func=_cmd_list)

    revoke = sub.add_parser("revoke", help="delete stored OAuth credentials for a provider")
    revoke.add_argument("--org", required=True, help="organization id")
    revoke.add_argument("--user", required=True, help="user id")
    revoke.add_argument("provider", choices=[p.value for p in OAuthProvider])
    revoke.set_defaults(func=_cmd_revoke)
    return parser


def main() -> None:
    settings = get_settings()
    if not settings.vault_configured:
        print(
            "Vault is not configured. Set VAULT_ADDR and VAULT_TOKEN (or AppRole creds).",
            file=sys.stderr,
        )
        sys.exit(1)
    args = _build_parser().parse_args()
    vault = make_credential_vault(settings)
    args.func(vault, args)


if __name__ == "__main__":
    main()
