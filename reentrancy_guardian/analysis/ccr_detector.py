#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from time import perf_counter
from typing import Any, Dict, List, Optional, Set, Tuple

from analysis.implicit_state import (
    CONTRACT_BALANCE_STATE,
    function_access_with_implicit_state,
    has_post_call_balance_dependency,
)
from config import normalize_classic_fallback_policy
from models import CCRCandidate


class CCRDetector:
    """Detect callback-style reentrancy candidates on the enhanced ICFG."""

    def __init__(
        self,
        icfg_builder: Any,
        semantic_analyzer: Any,
        lock_analyzer: Any,
        state_limit: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        enable_classic_fallback: bool = True,
        classic_fallback_policy: str = "normal",
        ablation_no_state_conflict: bool = False,
        ablation_no_state_access_propagation: bool = False,
        ablation_explicit_state_conflict_only: bool = False,
    ):
        self.icfg = icfg_builder
        self.semantic = semantic_analyzer
        self.lock_analyzer = lock_analyzer
        self.state_limit = state_limit if state_limit and state_limit > 0 else None
        self.time_budget_seconds = time_budget_seconds if time_budget_seconds and time_budget_seconds > 0 else None
        self.enable_classic_fallback = enable_classic_fallback
        self.classic_fallback_policy = normalize_classic_fallback_policy(classic_fallback_policy)
        self.ablation_no_state_conflict = ablation_no_state_conflict
        self.ablation_no_state_access_propagation = ablation_no_state_access_propagation
        self.ablation_explicit_state_conflict_only = ablation_explicit_state_conflict_only
        self.truncated = False
        self._deadline: Optional[float] = None
        self._external_call_cache: Dict[str, List[int]] = {}
        self._function_access_cache: Dict[str, Set[str]] = {}

    def detect(self) -> List[CCRCandidate]:
        candidates: List[CCRCandidate] = []
        self.truncated = False
        self._deadline = (
            perf_counter() + self.time_budget_seconds
            if self.time_budget_seconds is not None
            else None
        )

        for entry_func in self.identify_entry_functions():
            if self._budget_exceeded():
                break
            for call_node_id in self.find_external_calls(entry_func):
                if self._budget_exceeded():
                    break
                conflict = self.check_state_conflicts(entry_func, call_node_id)
                if not conflict:
                    continue

                precise_matches: List[CCRCandidate] = []
                fallback_matches: List[CCRCandidate] = []

                for callback_entry, callback_kind in self.find_callback_entries(
                    call_node_id,
                    conflict["relevant_states"],
                    entry_func,
                ):
                    callback_access = self._collect_function_access(callback_entry)
                    overlap = conflict["relevant_states"] & callback_access
                    if not overlap:
                        continue

                    path = self.build_path(call_node_id, self.icfg.get_function_entry(callback_entry))
                    lock_blocked, lock_id = self.check_lock_protection(path or [call_node_id])
                    candidate = self.create_candidate(
                        entry_func=entry_func,
                        call_node_id=call_node_id,
                        callback_entry=callback_entry,
                        callback_kind=callback_kind,
                        overlap_states=overlap,
                        path=path or [call_node_id],
                    )
                    candidate.call_type = self.icfg.nodes[call_node_id].call_type or "unknown"
                    candidate.lock_blocked = lock_blocked
                    candidate.lock_id = lock_id
                    classification = candidate.classification_label()
                    if conflict.get("mode") == "classic":
                        mode_description = "before local state is finalized"
                    elif conflict.get("mode") == "implicit_balance":
                        mode_description = "through a balance-dependent window"
                    else:
                        mode_description = "through an inconsistent state window"
                    candidate.reason = (
                        f"{classification} detected: external call in {entry_func} can re-enter "
                        f"{callback_entry} {mode_description}, and both touch states {sorted(overlap)}"
                    )
                    if callback_kind == "cross_contract":
                        precise_matches.append(candidate)
                    else:
                        fallback_matches.append(candidate)

                # Keep precise cross-contract callbacks without discarding
                # same-contract fallback callbacks. This preserves recall when
                # low-level target resolution is partial or imprecise.
                candidates.extend(precise_matches)
                candidates.extend(fallback_matches)

        return self._dedupe(candidates)

    def identify_entry_functions(self) -> List[str]:
        entries: List[str] = []
        for func_key, meta in self.icfg.function_meta.items():
            if meta.get("visibility") not in {"public", "external"}:
                continue
            if meta.get("readonly"):
                continue
            if meta.get("is_constructor"):
                continue
            if self.find_external_calls(func_key):
                entries.append(func_key)
        return entries

    def find_external_calls(self, function: str) -> List[int]:
        if function in self._external_call_cache:
            return list(self._external_call_cache[function])

        call_nodes: List[int] = []
        for node_id in sorted(self.icfg.get_execution_slice(function, max_states=self.state_limit)):
            if self._budget_exceeded():
                break
            node = self.icfg.nodes.get(node_id)
            if not node or not node.is_reentrancy_sink():
                continue
            if node.call_type == "high_level_call":
                target_key = f"{node.call_target_contract}.{node.call_target_function}"
                target_meta = self.icfg.function_meta.get(target_key, {})
                if target_meta.get("readonly") and not self._is_dynamic_dispatch_call(node):
                    continue
            call_nodes.append(node_id)
        self._external_call_cache[function] = list(call_nodes)
        return list(call_nodes)

    def find_callback_entries(
        self,
        call_node_id: int,
        relevant_states: Optional[Set[str]] = None,
        entry_func: Optional[str] = None,
    ) -> List[Tuple[str, str]]:
        targets: List[Tuple[str, str]] = []
        for edge_type, callback_kind in (
            ("callback_cross_contract", "cross_contract"),
        ):
            for entry_id in sorted(self.icfg.get_semantic_successors(call_node_id, edge_type)):
                node = self.icfg.nodes.get(entry_id)
                if not node:
                    continue
                if relevant_states is not None:
                    callback_access = self._collect_function_access(node.function_key)
                    if not (relevant_states & callback_access):
                        continue
                targets.append((node.function_key, callback_kind))

        if not self.enable_classic_fallback:
            return sorted(set(targets))

        call_node = self.icfg.nodes.get(call_node_id)
        if call_node:
            for func_key in self.icfg.get_functions_by_contract(call_node.contract_name):
                meta = self.icfg.function_meta.get(func_key, {})
                if meta.get("visibility") not in {"public", "external"}:
                    continue
                if meta.get("readonly"):
                    continue
                if meta.get("is_constructor"):
                    continue
                if (
                    self.classic_fallback_policy != "normal"
                    and entry_func
                    and func_key != entry_func
                    and self._is_access_controlled_function(func_key)
                ):
                    continue

                entry_id = self.icfg.get_function_entry(func_key)
                if entry_id is None or entry_id == call_node_id:
                    continue
                if not self._allow_classic_fallback_entry(call_node, func_key, entry_func, relevant_states):
                    continue

                if relevant_states is not None:
                    callback_access = self._collect_function_access(func_key)
                    if not (relevant_states & callback_access):
                        continue

                targets.append((func_key, "classic"))
        return sorted(set(targets))

    def _allow_classic_fallback_entry(
        self,
        call_node: Any,
        callback_func: str,
        entry_func: Optional[str] = None,
        relevant_states: Optional[Set[str]] = None,
    ) -> bool:
        if self.classic_fallback_policy == "normal":
            return True

        callback_name = callback_func.rsplit(".", 1)[-1].lower()
        source_name = str(getattr(call_node, "function_name", "") or "").lower()
        entry_name = self._function_name(entry_func) if entry_func else source_name

        if callback_name in {"fallback", "receive"}:
            return True
        if callback_name == entry_name:
            return True

        if self._is_admin_config_function(entry_name):
            return False
        if entry_func and self._is_access_controlled_function(entry_func):
            return False
        if self._is_reward_bookkeeping_cross_entry(entry_name, callback_name, relevant_states):
            return False

        if callback_name == source_name and source_name == entry_name:
            return True

        # Admin/config entry functions are a major source of weak same-contract
        # virtual callbacks, especially when the actual call is reached through
        # an internal helper and the call node no longer carries the entry name.
        if self._is_low_level_value_or_dynamic_call(call_node):
            return True

        # Keep a second guard for direct high-level config calls when no entry
        # function was supplied by older callers/tests.
        if self._is_high_level_classic_fallback_call(call_node) and self._is_admin_config_entry(call_node):
            return False

        return True

    def _is_low_level_value_or_dynamic_call(self, call_node: Any) -> bool:
        call_type = str(getattr(call_node, "call_type", "") or "").lower()
        if call_type in {"low_level_call", "call", "delegatecall", "callcode"}:
            return True
        expression = self._normalize_expression(getattr(call_node, "expression", ""))
        return (
            "call{value:" in expression
            or ".call.value" in expression
            or ".send(" in expression
        )

    def _is_high_level_classic_fallback_call(self, call_node: Any) -> bool:
        return str(getattr(call_node, "call_type", "") or "").lower() == "high_level_call"

    def _is_admin_config_entry(self, call_node: Any) -> bool:
        name = str(getattr(call_node, "function_name", "") or "").lower()
        return self._is_admin_config_function(name)

    def _is_admin_config_function(self, name: str) -> bool:
        exact = {
            "renounceownership",
            "transferownership",
            "pause",
            "unpause",
            "stop",
            "start",
            "setowner",
            "set_owner",
            "settrader",
            "set_trader",
        }
        prefixes = (
            "update",
            "configure",
            "toggle",
        )
        is_setter = name.startswith("set") and not name.startswith("settle")
        is_protocol_approval = name.startswith("approve") and name != "approve"
        return name in exact or is_setter or is_protocol_approval or any(name.startswith(prefix) for prefix in prefixes)

    def _is_access_controlled_function(self, func_key: str) -> bool:
        if not self.icfg:
            return False
        meta = self.icfg.function_meta.get(func_key, {})
        modifiers = [str(modifier or "").lower() for modifier in meta.get("modifiers", [])]
        privileged_patterns = (
            "onlyowner",
            "onlyadmin",
            "onlymanager",
            "onlyoperator",
            "onlygovernance",
            "onlygovernor",
            "onlycontroller",
            "onlyfactory",
            "onlyminter",
            "ownerormanager",
        )
        return any(
            any(pattern in modifier for pattern in privileged_patterns)
            for modifier in modifiers
        )

    def _is_reward_bookkeeping_cross_entry(
        self,
        entry_name: str,
        callback_name: str,
        relevant_states: Optional[Set[str]],
    ) -> bool:
        if entry_name == callback_name:
            return False
        if not self._is_reward_bookkeeping_callback(callback_name, relevant_states):
            return False
        return self._is_token_bookkeeping_entry(entry_name) or self._is_reward_bookkeeping_entry(entry_name)

    def _is_reward_bookkeeping_callback(
        self,
        callback_name: str,
        relevant_states: Optional[Set[str]],
    ) -> bool:
        if not any(marker in callback_name for marker in ("claim", "reward", "dividend")):
            return False
        states = {self._normalize_expression(state) for state in (relevant_states or set())}
        reward_state_markers = (
            "reward",
            "dividend",
            "lastclaim",
            "totalexcluded",
            "totalrealised",
            "withdrawn",
        )
        return any(any(marker in state for marker in reward_state_markers) for state in states)

    def _is_token_bookkeeping_entry(self, name: str) -> bool:
        return name in {
            "approve",
            "burn",
            "burnfrom",
            "decreaseallowance",
            "decreaseapproval",
            "deliver",
            "increaseallowance",
            "increaseapproval",
            "mint",
            "transfer",
            "transferfrom",
        }

    def _is_reward_bookkeeping_entry(self, name: str) -> bool:
        return any(marker in name for marker in ("claim", "reward", "dividend"))

    def _function_name(self, func_key: str) -> str:
        return str(func_key or "").rsplit(".", 1)[-1].lower()

    def _normalize_expression(self, expression: Any) -> str:
        return "".join(str(expression or "").lower().split())

    def check_state_conflicts(self, entry_func: str, call_node_id: int) -> Optional[Dict[str, Any]]:
        entry_id = self.icfg.get_function_entry(entry_func)
        if entry_id is None:
            return None

        state_slice = self.icfg.get_execution_state_slice(entry_func, max_states=self.state_limit)
        self._mark_state_limit_if_hit(state_slice)
        call_states = {state for state in state_slice if state[0] == call_node_id}
        if not call_states:
            return None

        if self.ablation_no_state_conflict:
            reads, writes = self.icfg.get_function_state_access(entry_func)
            relevant_states = set(reads) | set(writes)
            if not relevant_states:
                relevant_states = {CONTRACT_BALANCE_STATE}
            return {
                "mode": "ablation_no_state_conflict",
                "pre_writes": set(),
                "post_access": set(),
                "post_writes": set(),
                "relevant_states": relevant_states,
            }

        pre_writes: Set[str] = set()
        post_access: Set[str] = set()
        post_writes: Set[str] = set()

        post_states = self.icfg.get_reachable_execution_states(
            call_states,
            max_depth=128,
            max_states=self.state_limit,
        )
        self._mark_state_limit_if_hit(post_states)
        reachability_cache: Dict[Tuple[int, Tuple[int, ...]], Set[Tuple[int, Tuple[int, ...]]]] = {}

        for state in state_slice:
            if self._budget_exceeded():
                return None
            node_id, _ = state
            if node_id == call_node_id:
                continue
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            if self.ablation_no_state_access_propagation and node.function_key != entry_func:
                continue
            reachable = reachability_cache.setdefault(
                state,
                self.icfg.get_reachable_execution_states(
                    {state},
                    max_depth=128,
                    max_states=self.state_limit,
                ),
            )
            self._mark_state_limit_if_hit(reachable)
            if any(call_state in reachable for call_state in call_states):
                pre_writes.update(node.writes)

        for node_id, _ in post_states:
            if node_id == call_node_id:
                continue
            node = self.icfg.nodes.get(node_id)
            if node:
                if self.ablation_no_state_access_propagation and node.function_key != entry_func:
                    continue
                post_access.update(node.reads | node.writes)
                post_writes.update(node.writes)

        overlap = pre_writes & post_access
        if overlap:
            return {
                "mode": "window",
                "pre_writes": pre_writes,
                "post_access": post_access,
                "post_writes": post_writes,
                "relevant_states": overlap,
            }

        if self.ablation_explicit_state_conflict_only:
            return None

        if not post_writes:
            if has_post_call_balance_dependency(self.icfg, post_states):
                return {
                    "mode": "implicit_balance",
                    "pre_writes": pre_writes,
                    "post_access": post_access,
                    "post_writes": post_writes,
                    "relevant_states": {CONTRACT_BALANCE_STATE},
                }
            return None
        return {
            "mode": "classic",
            "pre_writes": pre_writes,
            "post_access": post_access,
            "post_writes": post_writes,
            "relevant_states": post_writes,
        }

    def check_lock_protection(self, path_nodes: List[int]) -> Tuple[bool, Optional[str]]:
        if not self.lock_analyzer:
            return False, None
        for node_id in path_nodes:
            scope = self.lock_analyzer.get_protecting_lock(node_id)
            if scope:
                return True, scope.lock_id
        return False, None

    def build_path(self, start_node: int, end_node: Optional[int]) -> List[int]:
        if end_node is None:
            return [start_node]
        path = self.icfg.find_path(
            start_node,
            end_node,
            semantic_types={"callback", "callback_cross_contract", "alias", "delegatecall"},
        )
        return path or [start_node, end_node]

    def create_candidate(
        self,
        entry_func: str,
        call_node_id: int,
        callback_entry: str,
        callback_kind: str,
        overlap_states: Set[str],
        path: List[int],
    ) -> CCRCandidate:
        source_contract, entry_function = entry_func.split(".", 1)
        target_contract, callback_entry_function = callback_entry.split(".", 1)
        return CCRCandidate(
            candidate_id=f"ccr_{source_contract}_{entry_function}_{call_node_id}_{callback_entry_function}",
            source_contract=source_contract,
            entry_function=entry_function,
            external_call_node=call_node_id,
            target_contract=target_contract,
            callback_entry_function=callback_entry_function,
            callback_kind=callback_kind,
            overlap_states=overlap_states,
            path_node_ids=path,
        )

    def _collect_function_access(self, func_key: str) -> Set[str]:
        if func_key not in self._function_access_cache:
            if self.ablation_no_state_access_propagation:
                reads, writes = self.icfg.get_function_state_access(func_key)
                self._function_access_cache[func_key] = set(reads) | set(writes)
            else:
                self._function_access_cache[func_key] = function_access_with_implicit_state(self.icfg, func_key)
        return set(self._function_access_cache[func_key])

    def _is_dynamic_dispatch_call(self, node: Any) -> bool:
        expression = str(getattr(node, "expression", "") or "")
        dynamic_markers = ("msg.sender", "msg_sender", "tx.origin", "tx_origin")
        return any(marker in expression for marker in dynamic_markers)

    def _budget_exceeded(self) -> bool:
        if self._deadline is None:
            return False
        if perf_counter() <= self._deadline:
            return False
        self.truncated = True
        return True

    def _mark_state_limit_if_hit(self, states: Set[Tuple[int, Tuple[int, ...]]]) -> None:
        if self.state_limit is not None and len(states) >= self.state_limit:
            self.truncated = True

    def _dedupe(self, candidates: List[CCRCandidate]) -> List[CCRCandidate]:
        deduped: Dict[str, CCRCandidate] = {}
        for candidate in candidates:
            key = (
                candidate.source_contract,
                candidate.entry_function,
                candidate.external_call_node,
                candidate.callback_entry_function,
                candidate.callback_kind,
                tuple(sorted(candidate.overlap_states)),
            )
            deduped[str(key)] = candidate
        return list(deduped.values())
