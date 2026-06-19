"""The offline heuristic planner and post-plan routing.

These cover the planner's intent detection and the security-relevant routing rule: any gated action
must route to the approval node.
"""

from atlas.actions import RiskTier
from atlas.orchestration.nodes import heuristic_plan, route_after_planner
from atlas.tools import default_registry


def test_send_intent_proposes_gated_email_with_extracted_recipient() -> None:
    registry = default_registry()
    actions = heuristic_plan("Please email alice@example.com the update", registry, [])
    sends = [a for a in actions if a.tool == "send_email"]
    assert len(sends) == 1
    assert sends[0].risk_tier is RiskTier.SEND
    assert sends[0].args["to"] == "alice@example.com"


def test_search_intent_proposes_read_action() -> None:
    registry = default_registry()
    actions = heuristic_plan("find the revenue figures", registry, [])
    assert any(a.tool == "search" and a.risk_tier is RiskTier.READ for a in actions)


def test_no_recognized_intent_proposes_nothing() -> None:
    registry = default_registry()
    assert heuristic_plan("hello there", registry, []) == []


def test_route_sends_gated_action_to_approval() -> None:
    registry = default_registry()
    gated = registry.propose("send_email", {"to": "a@b.com"})
    assert route_after_planner({"proposed_actions": [gated]}) == "approval"


def test_route_sends_read_only_action_to_executor() -> None:
    registry = default_registry()
    read = registry.propose("search", {"query": "x"})
    assert route_after_planner({"proposed_actions": [read]}) == "executor"


def test_route_with_no_actions_goes_to_responder() -> None:
    assert route_after_planner({"proposed_actions": []}) == "responder"
