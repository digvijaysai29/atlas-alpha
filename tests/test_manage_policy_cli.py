"""Offline CLI tests for scripts/manage_policy.py."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_manage_policy_exits_nonzero_without_database_url() -> None:
    env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    result = subprocess.run(
        [sys.executable, str(_REPO_ROOT / "scripts" / "manage_policy.py"), "list"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
