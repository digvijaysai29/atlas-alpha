"""Back-compat shim — the eval gate now lives in :mod:`evals.run_gate`.

Historically the ``agent-eval`` CI job invoked ``evals/run_evals.py``. M2.3 replaced the no-op gate
with a real hybrid gate (blocking deterministic security oracles + optional non-blocking LangSmith
quality evals). CI now calls ``evals/run_gate.py`` directly; this shim is kept so any external caller
of the old path still runs the real gate.
"""

from __future__ import annotations

import pathlib
import sys

_REPO_ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from evals.run_gate import MIN_PASS_SCORE, main  # noqa: E402,F401  (re-export for back-compat)

if __name__ == "__main__":
    sys.exit(main())
