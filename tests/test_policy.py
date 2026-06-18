"""The approval policy is the trust boundary — it gets the most scrutiny.

Covers the risk-tier mapping and, critically, the **fail-closed** behavior for unknown/missing tiers.
"""

import pytest

from atlas.actions import RiskTier, requires_approval


def test_read_is_the_only_auto_approved_tier() -> None:
    assert requires_approval(RiskTier.READ) is False


@pytest.mark.parametrize("tier", [RiskTier.WRITE, RiskTier.SEND, RiskTier.DELETE, RiskTier.PAY])
def test_side_effecting_tiers_require_approval(tier: RiskTier) -> None:
    assert requires_approval(tier) is True


def test_unknown_string_tier_is_fail_closed() -> None:
    assert requires_approval("frobnicate") is True


def test_none_tier_is_fail_closed() -> None:
    assert requires_approval(None) is True


def test_valid_string_tiers_round_trip() -> None:
    assert requires_approval("read") is False
    assert requires_approval("send") is True


def test_risk_tier_is_auto_safe_property() -> None:
    assert RiskTier.READ.is_auto_safe is True
    assert RiskTier.SEND.is_auto_safe is False
