"""atlas — an agent-first enterprise workspace.

The package is organized by feature/domain:

- ``config``       : environment-driven settings (secrets via env only)
- ``llm``          : Claude model factory
- ``actions``      : risk tiers, immutable action contracts, the approval policy
- ``tools``        : the Tool protocol, the registry, and mock tools
- ``governance``   : the append-only audit log
- ``orchestration``: the LangGraph state machine (the core of atlas)
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
