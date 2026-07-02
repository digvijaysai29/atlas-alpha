"""Tests for the metadata-driven adapter engine (M4.8a).

Two themes:
1. **Equivalence** — a schema-built tool behaves like its hand-written twin (``slack_post_as_user``):
   same proposed action, same payload, same result shape.
2. **Security** — the constraints that make a data-driven tool factory safe are enforced: risk tier
   stays code-anchored (a schema cannot declare an auto-run READ), egress is host-allowlisted (SSRF),
   tokens are server-resolved, and malformed schemas fail closed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from atlas.actions import RiskTier, requires_approval
from atlas.adapter_engine import (
    AdapterEngine,
    ToolSchema,
    ToolSchemaError,
    load_schema,
    load_schema_dir,
    packaged_schema_dir,
)
from atlas.config import Settings
from atlas.governance.credentials import (
    CredentialResolver,
    InMemoryCredentialVault,
    OAuthProvider,
    StoredCredential,
)
from atlas.governance.rbac import Principal
from atlas.integrations.oauth import SLACK_USER_CHAT_WRITE, build_credential_resolver
from atlas.tool_egress import EgressNotAllowed, FakeTransport, ProxyTransport, Transport
from atlas.tools import BaseTool, SlackPostAsUserTool, ToolRegistry

_ALLOWLIST = frozenset({"slack.com"})
_PRINCIPAL = Principal(user_id="alice", roles=("member",), org_id="acme")


def _resolver_with_slack_token(token: str = "xoxp-tok") -> CredentialResolver:
    vault = InMemoryCredentialVault()
    vault.put(
        _PRINCIPAL,
        OAuthProvider.SLACK,
        StoredCredential(
            provider=OAuthProvider.SLACK,
            scopes=(SLACK_USER_CHAT_WRITE,),
            access_token=token,
        ),
    )
    resolver: CredentialResolver = build_credential_resolver(vault, Settings())
    return resolver


def _engine(
    transport: Transport | None,
    resolver: CredentialResolver | None = None,
    allowlist: frozenset[str] = _ALLOWLIST,
) -> AdapterEngine:
    return AdapterEngine(credential_resolver=resolver, transport=transport, allowlist=allowlist)


def _slack_schema_path() -> Path:
    return packaged_schema_dir() / "slack_post_as_user.json"


def _base_schema(**overrides: object) -> ToolSchema:
    data: dict[str, object] = {
        "name": "x_tool",
        "provider": "slack",
        "endpoint": "https://slack.com/api/chat.postMessage",
        "required_permission": "tool:test",
        "args": [{"name": "text", "type": "str"}],
        "payload": {"text": {"arg": "text"}},
    }
    data.update(overrides)
    return ToolSchema.model_validate(data)


# --- equivalence -----------------------------------------------------------


def test_packaged_slack_schema_matches_handwritten_metadata() -> None:
    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    handwritten = SlackPostAsUserTool()
    assert tool.name == handwritten.name
    assert tool.risk_tier == handwritten.risk_tier == RiskTier.SEND
    assert tool.required_permission == handwritten.required_permission == "tool:slack:post_as_user"


# --- slack_delete_message (M4.8d — new connector purely via schema) --------
def _delete_message_schema_path() -> Path:
    return packaged_schema_dir() / "slack_delete_message.json"


def test_slack_delete_message_schema_loads_and_validates() -> None:
    schema = load_schema(_delete_message_schema_path())
    assert schema.name == "slack_delete_message"
    assert schema.risk_tier is RiskTier.DELETE
    assert schema.required_permission == "tool:slack:delete_message"
    assert schema.provider.value == "slack"
    assert schema.required_scopes == ("chat:write",)  # reuses slack_post_as_user's existing scope
    assert schema.endpoint == "https://slack.com/api/chat.delete"


def test_slack_delete_message_requires_approval() -> None:
    # DELETE is not READ, so it stays gated exactly like every other non-read schema tool.
    schema = load_schema(_delete_message_schema_path())
    assert requires_approval(schema.risk_tier) is True


def test_slack_delete_message_builds_via_adapter_engine() -> None:
    schema = load_schema(_delete_message_schema_path())
    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(schema)
    assert tool.name == "slack_delete_message"
    assert tool.risk_tier is RiskTier.DELETE
    assert tool.required_permission == "tool:slack:delete_message"


def test_slack_delete_message_proposal_and_execution() -> None:
    registry = ToolRegistry()
    transport = FakeTransport(_ALLOWLIST, response={"ok": True, "channel": "C1", "ts": "123.45"})
    tool = _engine(transport, _resolver_with_slack_token()).build_tool(
        load_schema(_delete_message_schema_path())
    )
    registry.register(tool)
    action = registry.propose("slack_delete_message", {"channel": "C1", "ts": "123.45"})
    assert action.risk_tier is RiskTier.DELETE
    result = registry.execute(action, _PRINCIPAL)
    assert result.ok is True
    assert result.output == {"channel": "C1", "ts": "123.45", "provider": "slack"}
    assert transport.calls[0][1] == {"channel": "C1", "ts": "123.45"}  # flat payload, no nesting


def test_load_schema_dir_includes_both_bundled_schemas() -> None:
    schemas = {s.name for s in load_schema_dir(packaged_schema_dir())}
    assert schemas == {"slack_post_as_user", "slack_delete_message"}


def test_proposed_action_equivalent_to_handwritten() -> None:
    schema_tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    schema_reg = ToolRegistry()
    schema_reg.register(schema_tool)
    hand_reg = ToolRegistry()
    hand_reg.register(SlackPostAsUserTool())

    args = {"channel": "C123", "text": "hello"}
    schema_action = schema_reg.propose("slack_post_as_user", args)
    hand_action = hand_reg.propose("slack_post_as_user", args)

    assert schema_action.tool == hand_action.tool
    assert schema_action.args == hand_action.args == {"channel": "C123", "text": "hello"}
    assert schema_action.risk_tier == hand_action.risk_tier == RiskTier.SEND


def test_execution_produces_slack_user_result_shape_and_payload() -> None:
    transport = FakeTransport(
        _ALLOWLIST, response={"ok": True, "ts": "1700000000.0001", "channel": "C123"}
    )
    tool = _engine(transport, _resolver_with_slack_token("xoxp-abc")).build_tool(
        load_schema(_slack_schema_path())
    )
    args = tool.ArgsSchema.model_validate({"channel": "C123", "text": "hello"})

    output = tool.run(args, principal=_PRINCIPAL)

    # Same shape SlackUserApiSender.post returns: {ts, channel, provider: "slack_user"}.
    assert output == {"ts": "1700000000.0001", "channel": "C123", "provider": "slack_user"}
    url, payload, sent_token = transport.calls[0]
    assert url == "https://slack.com/api/chat.postMessage"
    assert sent_token == "xoxp-abc"  # server-resolved from the principal, not from args
    assert payload == {
        "channel": "C123",
        "text": "hello",
        "unfurl_links": False,
        "unfurl_media": False,
    }


def test_schema_tool_is_approval_gated() -> None:
    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    assert requires_approval(tool.risk_tier) is True


def test_generated_args_enforce_constraints() -> None:
    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    with pytest.raises(ValidationError):
        tool.ArgsSchema.model_validate({"channel": "", "text": "hi"})  # channel min_length 1
    with pytest.raises(ValidationError):
        tool.ArgsSchema.model_validate({"channel": "C1", "text": "x" * 40001})  # text max_length


# --- security: risk tier stays code-anchored -------------------------------


def test_schema_cannot_declare_auto_run_read() -> None:
    schema = _base_schema(name="sneaky", risk_tier="read")
    with pytest.raises(ToolSchemaError):
        _engine(FakeTransport(_ALLOWLIST)).build_tool(schema)


def test_schema_defaults_to_send_tier_when_unspecified() -> None:
    assert _base_schema().risk_tier is RiskTier.SEND


def test_side_effecting_schema_without_permission_rejected() -> None:
    # A SEND tool with no required_permission would bypass the RBAC default-deny layer.
    schema = _base_schema(required_permission=None)
    with pytest.raises(ToolSchemaError):
        _engine(FakeTransport(_ALLOWLIST)).build_tool(schema)


@pytest.mark.parametrize("bad_name", ["model_config", "1bad", "__init__", "Channel", "with-dash"])
def test_arg_name_must_be_safe_identifier(bad_name: str) -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "required_permission": "tool:x",
                "args": [{"name": bad_name, "type": "str"}],
            }
        )


# --- security: SSRF egress allowlist ---------------------------------------


def test_endpoint_host_not_on_allowlist_rejected_at_build() -> None:
    schema = _base_schema(endpoint="https://evil.example.com/x")
    with pytest.raises(EgressNotAllowed):
        _engine(FakeTransport(None), allowlist=_ALLOWLIST).build_tool(schema)


def test_http_endpoint_rejected_at_build() -> None:
    schema = _base_schema(endpoint="http://slack.com/x")
    with pytest.raises(EgressNotAllowed):
        _engine(FakeTransport(_ALLOWLIST), allowlist=_ALLOWLIST).build_tool(schema)


def test_transport_rechecks_allowlist_at_call_time() -> None:
    transport = FakeTransport(_ALLOWLIST)
    with pytest.raises(EgressNotAllowed):
        transport.post_json("https://evil.example.com/x", json={}, access_token="t")


# --- security: fail-closed execution + schema validation -------------------


def test_run_without_resolver_or_transport_fails_closed() -> None:
    tool = _engine(transport=None, resolver=None).build_tool(load_schema(_slack_schema_path()))
    args = tool.ArgsSchema.model_validate({"channel": "C1", "text": "hi"})
    with pytest.raises(RuntimeError):
        tool.run(args, principal=_PRINCIPAL)


def test_ok_false_response_raises() -> None:
    transport = FakeTransport(_ALLOWLIST, response={"ok": False, "error": "channel_not_found"})
    tool = _engine(transport, _resolver_with_slack_token()).build_tool(
        load_schema(_slack_schema_path())
    )
    args = tool.ArgsSchema.model_validate({"channel": "C1", "text": "hi"})
    with pytest.raises(RuntimeError, match="channel_not_found"):
        tool.run(args, principal=_PRINCIPAL)


def test_unknown_schema_field_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "bogus": 1,
            }
        )


def test_payload_field_requires_exactly_one_of_arg_or_value() -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "args": [{"name": "t", "type": "str"}],
                "payload": {"t": {"arg": "t", "value": "c"}},
            }
        )


def test_payload_references_undeclared_arg_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "args": [{"name": "t", "type": "str"}],
                "payload": {"x": {"arg": "missing"}},
            }
        )


def test_apply_adapter_engine_replaces_handwritten_tool() -> None:
    from atlas.orchestration.graph import _apply_adapter_engine

    registry = ToolRegistry()
    registry.register(SlackPostAsUserTool())
    _apply_adapter_engine(registry, Settings(), None)

    tool = registry.get("slack_post_as_user")
    assert not isinstance(tool, SlackPostAsUserTool)
    assert type(tool).__name__ == "_SchemaTool"
    assert isinstance(tool.ArgsSchema, type) and issubclass(tool.ArgsSchema, BaseModel)


def test_apply_adapter_engine_uses_proxy_transport_when_configured() -> None:
    from atlas.orchestration.graph import _apply_adapter_engine

    registry = ToolRegistry()
    settings = Settings(ATLAS_ADAPTER_EGRESS_PROXY_URL="http://egress.internal:8080")
    _apply_adapter_engine(registry, settings, None)
    tool = registry.get("slack_post_as_user")
    assert type(tool).__name__ == "_SchemaTool"
    transport = getattr(tool, "_transport")
    assert isinstance(transport, ProxyTransport)


def test_load_schema_dir_raises_when_directory_missing(tmp_path: Path) -> None:
    with pytest.raises(ToolSchemaError, match="does not exist"):
        load_schema_dir(tmp_path / "nope")


def test_load_schema_dir_raises_when_no_json_files(tmp_path: Path) -> None:
    with pytest.raises(ToolSchemaError, match="no \\*.json schemas"):
        load_schema_dir(tmp_path)


def test_apply_adapter_engine_fails_when_schema_dir_empty(tmp_path: Path) -> None:
    from atlas.orchestration.graph import _apply_adapter_engine

    registry = ToolRegistry()
    registry.register(SlackPostAsUserTool())
    settings = Settings(ATLAS_ADAPTER_SCHEMA_DIR=str(tmp_path))
    with pytest.raises(ToolSchemaError, match="no \\*.json schemas"):
        _apply_adapter_engine(registry, settings, None)
    assert isinstance(registry.get("slack_post_as_user"), SlackPostAsUserTool)


def test_adapter_engine_without_database_url_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from atlas.orchestration import build_graph

    with caplog.at_level(logging.WARNING, logger="atlas.orchestration.graph"):
        build_graph(settings=Settings(ATLAS_ADAPTER_ENGINE_ENABLED=True, DATABASE_URL=None))
    assert any("Adapter engine is enabled" in record.message for record in caplog.records)


def test_payload_field_rejects_null_arg() -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "required_permission": "tool:x",
                "args": [{"name": "t", "type": "str"}],
                "payload": {"t": {"arg": None}},
            }
        )


def test_response_field_rejects_null_path() -> None:
    with pytest.raises(ValidationError):
        ToolSchema.model_validate(
            {
                "name": "x",
                "provider": "slack",
                "endpoint": "https://slack.com/x",
                "required_permission": "tool:x",
                "response": {"ts": {"path": None}},
            }
        )


def test_shape_response_missing_path_raises() -> None:
    transport = FakeTransport(_ALLOWLIST, response={"ok": True})
    tool = _engine(transport, _resolver_with_slack_token()).build_tool(
        load_schema(_slack_schema_path())
    )
    args = tool.ArgsSchema.model_validate({"channel": "C1", "text": "hi"})
    with pytest.raises(RuntimeError, match="provider response missing required field"):
        tool.run(args, principal=_PRINCIPAL)


def test_audit_tool_context_rejects_forbidden_keys() -> None:
    from atlas.governance.audit import AuditToolContext

    with pytest.raises(ValidationError):
        AuditToolContext.model_validate({"access_token": "x"})


# --- reconstructable audit (M4.8b) -----------------------------------------


def test_schema_tool_audit_metadata_has_no_secret() -> None:
    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    meta = tool.audit_metadata()
    assert meta == {
        "schema": "slack_post_as_user",
        "schema_version": "1",
        "destination_host": "slack.com",
        "provider": "slack",
    }


def test_executor_audit_includes_schema_metadata_on_denial() -> None:
    from typing import cast

    from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore
    from atlas.orchestration.nodes import make_executor_node
    from atlas.orchestration.state import AgentState

    tool = _engine(FakeTransport(_ALLOWLIST)).build_tool(load_schema(_slack_schema_path()))
    registry = ToolRegistry()
    registry.register(tool)
    audit = InMemoryAuditLog()
    node = make_executor_node(registry, audit, InMemoryPolicyStore())
    action = registry.propose("slack_post_as_user", {"channel": "C1", "text": "hi"})
    state = cast(
        AgentState,
        {
            "principal": Principal.anonymous(),
            "proposed_actions": [action],
            "approved_action_ids": [],
        },
    )
    node(state)

    evt = audit.events()[-1]
    assert evt.event_type.value == "denied"  # policy outcome
    assert evt.action_id == action.action_id  # correlation id
    assert evt.detail["schema"] == "slack_post_as_user"
    assert evt.detail["schema_version"] == "1"
    assert evt.detail["destination_host"] == "slack.com"
    assert evt.detail["provider"] == "slack"
    assert evt.detail["principal"] == "anonymous"


def test_guarded_execution_audit_is_reconstructable_without_secrets() -> None:
    import json as _json

    from atlas.execution import GuardedExecutor
    from atlas.governance import InMemoryAuditLog

    transport = FakeTransport(_ALLOWLIST, response={"ok": True, "ts": "1.1", "channel": "C1"})
    tool = _engine(transport, _resolver_with_slack_token("xoxp-SECRET")).build_tool(
        load_schema(_slack_schema_path())
    )
    registry = ToolRegistry()
    registry.register(tool)
    audit = InMemoryAuditLog()
    action = registry.propose("slack_post_as_user", {"channel": "C1", "text": "hi"})
    from atlas.governance.audit import AuditToolContext

    meta = AuditToolContext(**tool.audit_metadata(), principal=_PRINCIPAL.user_id)

    GuardedExecutor(registry).execute_guarded(action, audit, _PRINCIPAL, extra=meta)

    evt = audit.events()[-1]
    assert evt.event_type.value == "executed"  # policy outcome
    assert evt.action_id == action.action_id  # correlation / approval receipt
    assert evt.detail["schema_version"] == "1"
    assert evt.detail["destination_host"] == "slack.com"
    assert evt.detail["provider"] == "slack"
    assert "xoxp-SECRET" not in _json.dumps(evt.model_dump(mode="json"))


def _slack_tool_and_registry(
    transport: Transport,
) -> tuple[BaseTool, ToolRegistry]:
    tool = _engine(transport, _resolver_with_slack_token("xoxp-SECRET")).build_tool(
        load_schema(_slack_schema_path())
    )
    registry = ToolRegistry()
    registry.register(tool)
    return tool, registry


def _assert_reconstructable_audit_detail(evt: object, *, principal_id: str) -> None:
    import json as _json

    detail = evt.detail  # type: ignore[attr-defined]
    assert detail["schema"] == "slack_post_as_user"
    assert detail["schema_version"] == "1"
    assert detail["destination_host"] == "slack.com"
    assert detail["provider"] == "slack"
    assert detail["principal"] == principal_id
    assert "xoxp-SECRET" not in _json.dumps(evt.model_dump(mode="json"))  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("event_type", "trigger"),
    [
        ("skipped", "executor_not_approved"),
        ("failed", "guarded_fail"),
        ("replay_skipped", "guarded_replay"),
    ],
)
def test_audit_metadata_on_all_executor_paths(event_type: str, trigger: str) -> None:
    from typing import cast

    from atlas.execution import GuardedExecutor
    from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore
    from atlas.governance.audit import AuditToolContext
    from atlas.orchestration.nodes import make_executor_node
    from atlas.orchestration.state import AgentState

    if trigger == "executor_not_approved":
        tool, registry = _slack_tool_and_registry(FakeTransport(_ALLOWLIST))
        audit = InMemoryAuditLog()
        node = make_executor_node(registry, audit, InMemoryPolicyStore())
        action = registry.propose("slack_post_as_user", {"channel": "C1", "text": "hi"})
        state = cast(
            AgentState,
            {
                "principal": _PRINCIPAL,
                "proposed_actions": [action],
                "approved_action_ids": [],
            },
        )
        node(state)
        evt = audit.events()[-1]
        assert evt.event_type.value == event_type
        _assert_reconstructable_audit_detail(evt, principal_id=_PRINCIPAL.user_id)
        return

    if trigger == "guarded_fail":
        transport = FakeTransport(_ALLOWLIST, fail=True)
        tool, registry = _slack_tool_and_registry(transport)
        audit = InMemoryAuditLog()
        action = registry.propose("slack_post_as_user", {"channel": "C1", "text": "hi"})
        meta = AuditToolContext(**tool.audit_metadata(), principal=_PRINCIPAL.user_id)
        GuardedExecutor(registry).execute_guarded(action, audit, _PRINCIPAL, extra=meta)
        evt = audit.events()[-1]
        assert evt.event_type.value == event_type
        _assert_reconstructable_audit_detail(evt, principal_id=_PRINCIPAL.user_id)
        return

    transport = FakeTransport(_ALLOWLIST, response={"ok": True, "ts": "1.1", "channel": "C1"})
    tool, registry = _slack_tool_and_registry(transport)
    audit = InMemoryAuditLog()
    action = registry.propose("slack_post_as_user", {"channel": "C1", "text": "hi"})
    meta = AuditToolContext(**tool.audit_metadata(), principal=_PRINCIPAL.user_id)
    GuardedExecutor(registry).execute_guarded(action, audit, _PRINCIPAL, extra=meta)
    GuardedExecutor(registry).execute_guarded(action, audit, _PRINCIPAL, extra=meta)
    evt = audit.events()[-1]
    assert evt.event_type.value == event_type
    _assert_reconstructable_audit_detail(evt, principal_id=_PRINCIPAL.user_id)
