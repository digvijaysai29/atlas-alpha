"""Metadata-driven adapter engine (M4.8a) — a tool *factory*, not a second security path.

The engine turns a trusted, version-controlled JSON :class:`ToolSchema` into a
:class:`~atlas.tools.BaseTool` instance that plugs into the existing :class:`~atlas.tools.ToolRegistry`.
Execution still flows through the unchanged orchestration gate — the executor node's RBAC re-check +
``action_id`` approval gate, the :class:`~atlas.execution.GuardedExecutor` idempotency, and the
hash-chained :class:`~atlas.governance.audit.AuditLog`. Nothing security-critical is reimplemented
here; the engine only supplies the per-tool *metadata + payload/egress shim* that today is hand-written
once per integration.

Security posture (fail-closed; the constraints that make this safe to be data-driven):

- **Risk tier stays code-anchored.** A schema may *reference* a :class:`~atlas.actions.RiskTier`, but
  it cannot mark a tool as an auto-run ``READ`` unless that tool name is on a code-reviewed allowlist
  (empty by default). Everything else defaults to / stays ``SEND`` and is therefore approval-gated.
  This preserves the invariant *"risk tier is tool-declared, never model/data-assigned."*
- **Schemas are a trusted build artifact** loaded from the package (or an operator-set dir) at startup
  — never user/network/LLM-supplied, never hot-loaded from an untrusted source.
- **SSRF-safe egress.** The endpoint host is validated against the egress allowlist at build time and
  re-checked by the transport at call time. The URL comes from the schema, never from tool args.
- **Tokens are server-resolved** via :class:`~atlas.governance.credentials.CredentialResolver`, scoped
  to ``(org_id, user_id)`` — never from args, never logged.
- **Declarative, non-eval transforms.** Payload/response mapping is a static field map (copy an arg or
  emit a constant); there is no expression evaluation or templating.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, create_model, model_validator

from atlas.actions import RiskTier
from atlas.governance.credentials import CredentialResolver, OAuthProvider
from atlas.governance.rbac import Principal
from atlas.tool_egress import (
    ALLOWED_METHOD,
    EgressPolicy,
    EgressRoute,
    Transport,
    assert_host_allowed,
)
from atlas.tools import BaseTool

# Schemas may declare an auto-run ``READ`` tier ONLY for tool names on this code-reviewed allowlist.
# Empty => no schema may be READ, so every schema-built tool is approval-gated. Lowering a tool to
# READ therefore requires a code change + review, never a config/JSON edit (anti approval-bypass).
_READ_TIER_ALLOWLIST: frozenset[str] = frozenset()


class ToolSchemaError(ValueError):
    """Raised when a tool schema is structurally invalid or violates a security constraint."""


class ArgSpec(BaseModel):
    """One declared tool argument, mapped to a generated Pydantic field. Immutable."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    type: Literal["str", "int", "bool"] = "str"
    required: bool = True
    # Length constraints apply to ``str`` args only; ignored for int/bool.
    min_length: int | None = None
    max_length: int | None = None
    description: str = ""


class PayloadField(BaseModel):
    """An outbound-payload field: copy a tool ``arg`` OR emit a constant ``value`` (exactly one)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    arg: str | None = None
    value: Any = None

    @model_validator(mode="after")
    def _exactly_one(self) -> PayloadField:
        has_arg = "arg" in self.model_fields_set
        has_value = "value" in self.model_fields_set
        if has_arg == has_value:
            raise ToolSchemaError("payload field must set exactly one of 'arg' or 'value'")
        return self


class ResponseField(BaseModel):
    """A shaped-result field: take a top-level ``path`` from the response OR a constant ``value``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str | None = None
    value: Any = None

    @model_validator(mode="after")
    def _exactly_one(self) -> ResponseField:
        has_path = "path" in self.model_fields_set
        has_value = "value" in self.model_fields_set
        if has_path == has_value:
            raise ToolSchemaError("response field must set exactly one of 'path' or 'value'")
        return self


class ToolSchema(BaseModel):
    """Declarative definition of an outbound tool. Immutable; validated at the boundary (fail-closed)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    description: str = ""
    # Schema files are versioned + code-reviewed (schemas-as-code). The version is logged in the audit
    # trail so a generated tool action can be tied back to the exact schema revision that produced it.
    schema_version: str = "1"
    # Defaults to the most-restrictive gated tier. A schema cannot make a tool auto-run READ unless it
    # is explicitly code-allowlisted (see _READ_TIER_ALLOWLIST), enforced in AdapterEngine.build_tool.
    risk_tier: RiskTier = RiskTier.SEND
    required_permission: str | None = None
    provider: OAuthProvider
    required_scopes: tuple[str, ...] = ()
    endpoint: str = Field(min_length=1)
    method: Literal["POST"] = "POST"
    args: tuple[ArgSpec, ...] = ()
    payload: dict[str, PayloadField] = Field(default_factory=dict)
    response: dict[str, ResponseField] = Field(default_factory=dict)
    # When set, the provider response must carry a truthy value at this key, else the call is an error.
    ok_field: str | None = "ok"

    @model_validator(mode="after")
    def _payload_args_declared(self) -> ToolSchema:
        declared = {a.name for a in self.args}
        for key, field in self.payload.items():
            if field.arg is not None and field.arg not in declared:
                raise ToolSchemaError(
                    f"payload field '{key}' references undeclared arg '{field.arg}'"
                )
        return self


def load_schema(path: Path) -> ToolSchema:
    """Load and validate a single tool schema from ``path`` (fail-closed on unknown/invalid fields)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ToolSchema.model_validate(raw)


def load_schema_dir(directory: Path) -> list[ToolSchema]:
    """Load every ``*.json`` schema in ``directory`` (sorted for deterministic order)."""
    return [load_schema(path) for path in sorted(directory.glob("*.json"))]


def build_egress_policy(schemas: list[ToolSchema], allowed_hosts: frozenset[str]) -> EgressPolicy:
    """Derive the runtime egress policy: the host allowlist plus an exact (method, host, path) route
    per schema, so a permitted host cannot be tunneled to arbitrary paths.

    Endpoints are parsed with ``httpx.URL`` — the same parser the transport connects with — so the
    route a schema declares is exactly the route the egress layer enforces (no parser differential).
    """
    routes = frozenset(
        EgressRoute(
            ALLOWED_METHOD, (httpx.URL(s.endpoint).host or "").lower(), httpx.URL(s.endpoint).path
        )
        for s in schemas
    )
    return EgressPolicy(allowed_hosts, routes)


def _build_args_model(schema: ToolSchema) -> type[BaseModel]:
    """Generate a Pydantic args model from the schema's declared args (validated at the boundary)."""
    type_map: dict[str, type] = {"str": str, "int": int, "bool": bool}
    field_defs: dict[str, Any] = {}
    for spec in schema.args:
        py_type = type_map[spec.type]
        constraints: dict[str, Any] = {"description": spec.description}
        if spec.type == "str":
            if spec.min_length is not None:
                constraints["min_length"] = spec.min_length
            if spec.max_length is not None:
                constraints["max_length"] = spec.max_length
        if spec.required:
            field_defs[spec.name] = (py_type, Field(**constraints))
        else:
            field_defs[spec.name] = (py_type | None, Field(default=None, **constraints))
    return create_model(f"{schema.name}_args", **field_defs)


def _build_payload(schema: ToolSchema, args: BaseModel) -> dict[str, Any]:
    """Map validated args -> outbound JSON payload via the schema's static field map (no eval)."""
    payload: dict[str, Any] = {}
    for key, field in schema.payload.items():
        payload[key] = getattr(args, field.arg) if field.arg is not None else field.value
    return payload


def _shape_response(schema: ToolSchema, data: dict[str, Any]) -> dict[str, Any]:
    """Shape the provider response into a result dict via the schema's static map (no eval)."""
    shaped: dict[str, Any] = {}
    for key, field in schema.response.items():
        shaped[key] = data.get(field.path) if field.path is not None else field.value
    return shaped


class _SchemaTool(BaseTool):
    """A :class:`BaseTool` whose behavior is supplied entirely by a validated :class:`ToolSchema`."""

    def __init__(
        self,
        schema: ToolSchema,
        args_model: type[BaseModel],
        *,
        credential_resolver: CredentialResolver | None,
        transport: Transport | None,
    ) -> None:
        self.name = schema.name
        self.description = schema.description
        self.risk_tier = schema.risk_tier
        self.ArgsSchema = args_model
        self.required_permission = schema.required_permission
        self._schema = schema
        self._resolver = credential_resolver
        self._transport = transport
        # Destination host derived from the same parser the egress uses (no parser differential).
        self._destination_host = (httpx.URL(schema.endpoint).host or "").lower()

    def audit_metadata(self) -> dict[str, Any]:
        """Non-secret context the executor folds into the audit event (reconstructability).

        Deliberately excludes the access token and request body — only the schema identity, its
        version, the destination host, and the provider (which credential family was used).
        """
        return {
            "schema": self._schema.name,
            "schema_version": self._schema.schema_version,
            "destination_host": self._destination_host,
            "provider": self._schema.provider.value,
        }

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        if not isinstance(args, self.ArgsSchema):
            raise TypeError(f"expected {self.ArgsSchema.__name__}, got {type(args).__name__}")
        if self._resolver is None or self._transport is None:
            raise RuntimeError(f"{self.name} not configured")
        # Token resolved server-side from the principal — never from args (IDOR/SSRF defense).
        token = self._resolver.get_access_token(
            principal, self._schema.provider, frozenset(self._schema.required_scopes)
        )
        payload = _build_payload(self._schema, args)
        data = self._transport.post_json(self._schema.endpoint, json=payload, access_token=token)
        ok_field = self._schema.ok_field
        if ok_field is not None and not data.get(ok_field):
            raise RuntimeError(str(data.get("error") or f"{self._schema.provider.value} API error"))
        return _shape_response(self._schema, data)


class AdapterEngine:
    """Builds schema-driven :class:`BaseTool` instances. Holds the shared egress + credential wiring."""

    def __init__(
        self,
        *,
        credential_resolver: CredentialResolver | None,
        transport: Transport | None,
        allowlist: frozenset[str],
        read_tier_allowlist: frozenset[str] = _READ_TIER_ALLOWLIST,
    ) -> None:
        self._resolver = credential_resolver
        self._transport = transport
        self._allowlist = allowlist
        self._read_tier_allowlist = read_tier_allowlist

    def build_tool(self, schema: ToolSchema) -> BaseTool:
        """Validate ``schema`` against the security constraints, then build a registry-ready tool."""
        self._validate_security(schema)
        args_model = _build_args_model(schema)
        return _SchemaTool(
            schema,
            args_model,
            credential_resolver=self._resolver,
            transport=self._transport,
        )

    def build_tools_from_dir(self, directory: Path) -> list[BaseTool]:
        """Build every ``*.json`` schema in ``directory`` (sorted for deterministic order)."""
        return [self.build_tool(load_schema(path)) for path in sorted(directory.glob("*.json"))]

    def _validate_security(self, schema: ToolSchema) -> None:
        # 1. A schema may not declare auto-run READ unless the tool name is code-allowlisted.
        if schema.risk_tier is RiskTier.READ and schema.name not in self._read_tier_allowlist:
            raise ToolSchemaError(
                f"schema '{schema.name}' may not declare auto-run READ tier (not code-allowlisted)"
            )
        # 2. The endpoint host must be on the egress allowlist (transport re-checks at call time).
        assert_host_allowed(schema.endpoint, self._allowlist)


def packaged_schema_dir() -> Path:
    """The bundled tool-schema directory shipped alongside this module."""
    return Path(__file__).parent / "tool_schemas"
