#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SinkRuleManager - Critical sink identification heuristics.
"""

from typing import Any, Callable, Dict, List
from enum import Enum
from dataclasses import dataclass


class SinkCategory(Enum):
    PRICE_CALCULATION = "price_calculation"
    SHARE_ISSUANCE = "share_issuance"
    ASSET_TRANSFER = "asset_transfer"
    LIQUIDATION_CHECK = "liquidation_check"
    COLLATERAL_RATIO = "collateral_ratio"
    BALANCE_UPDATE = "balance_update"
    PERMISSION_CHECK = "permission_check"


@dataclass
class SinkRule:
    category: SinkCategory
    description: str
    pattern_matchers: List[Callable[[str], bool]]
    impact_level: str


class SinkRuleManager:
    """Small but practical sink rules for DeFi-style business logic."""

    def __init__(self):
        self.rules: Dict[str, SinkRule] = {}
        self._init_default_rules()

    def _init_default_rules(self):
        self.rules = {
            "share_issuance": SinkRule(
                category=SinkCategory.SHARE_ISSUANCE,
                description="Share mint/burn logic that is sensitive to stale price or balance data",
                pattern_matchers=[
                    lambda name: any(
                        token in name for token in {"deposit", "mint", "redeem", "stake", "unstake"}
                    )
                ],
                impact_level="high",
            ),
            "asset_transfer": SinkRule(
                category=SinkCategory.ASSET_TRANSFER,
                description="Asset transfer or withdrawal logic",
                pattern_matchers=[
                    lambda name: any(
                        token in name
                        for token in {"withdraw", "transfer", "swap", "borrow", "liquidate", "repay"}
                    )
                ],
                impact_level="high",
            ),
            "price_calc": SinkRule(
                category=SinkCategory.PRICE_CALCULATION,
                description="Price, quote, or exchange-rate sensitive logic",
                pattern_matchers=[
                    lambda name: any(token in name for token in {"price", "rate", "quote", "valuation"})
                ],
                impact_level="medium",
            ),
        }

    def add_rule(self, rule_id: str, rule: SinkRule):
        self.rules[rule_id] = rule

    def identify_sinks(self, function: Any) -> List[Dict[str, Any]]:
        function_name = ""
        node_ids: List[int] = []
        if isinstance(function, dict):
            function_name = str(function.get("name", "")).lower()
            node_ids = list(function.get("nodes", []))
        else:
            function_name = str(
                getattr(function, "function_name", None) or getattr(function, "name", "") or ""
            ).lower()
            if hasattr(function, "node_id"):
                node_ids = [getattr(function, "node_id")]

        matches: List[Dict[str, Any]] = []
        for rule_id, rule in self.rules.items():
            if any(matcher(function_name) for matcher in rule.pattern_matchers):
                matches.append(
                    {
                        "category": rule.category.value,
                        "node_ids": node_ids,
                        "rule_id": rule_id,
                        "impact": rule.impact_level,
                    }
                )
        return matches

    def is_critical_operation(self, node: Any) -> bool:
        function_name = str(
            getattr(node, "function_name", None) or getattr(node, "name", "") or ""
        ).lower()
        state_tokens = {
            str(token).lower() for token in getattr(node, "reads", set()) | getattr(node, "writes", set())
        }

        if getattr(node, "call_type", None) in {"high_level_call", "low_level_call", "call", "delegatecall"}:
            return True
        if any(matcher(function_name) for rule in self.rules.values() for matcher in rule.pattern_matchers):
            return True
        return any(
            keyword in token
            for token in state_tokens
            for keyword in {"balance", "share", "price", "rate", "liquidity", "collateral", "debt"}
        )

    def get_sinks_by_category(self, category: SinkCategory) -> List[SinkRule]:
        return [r for r in self.rules.values() if r.category == category]

    def match_pattern(self, function: Any, pattern: str) -> bool:
        function_name = str(
            getattr(function, "function_name", None)
            or getattr(function, "name", None)
            or function
            or ""
        ).lower()
        return pattern.lower() in function_name
