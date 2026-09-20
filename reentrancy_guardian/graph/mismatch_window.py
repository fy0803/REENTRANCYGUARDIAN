#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional, Set

from models import MismatchWindow


SHARE_PRICE_QUERY_HINTS = (
    "priceper",
    "price_per",
    "pricepershare",
    "price_per_share",
    "getprice",
    "exchange",
    "rate",
    "totalassets",
    "total_assets",
    "converttoassets",
    "convert_to_assets",
    "converttoshares",
    "convert_to_shares",
    "preview",
    "calc_token_amount",
)

SHARE_ACCOUNTING_STATE_HINTS = (
    "supply",
    "share",
    "shares",
    "balance",
    "balances",
    "asset",
    "assets",
    "liquidity",
)


class MismatchWindowDetector:
    """Extract state mismatch windows around external calls."""

    def __init__(
        self,
        icfg_builder: Any,
        contracts_info: Dict[str, Any],
        *,
        ablation_no_state_access_propagation: bool = False,
    ):
        self.icfg = icfg_builder
        self.contracts_info = contracts_info
        self.mismatch_windows: Dict[str, MismatchWindow] = {}
        self.ablation_no_state_access_propagation = ablation_no_state_access_propagation

    def detect_windows(self) -> Dict[str, MismatchWindow]:
        windows: Dict[str, MismatchWindow] = {}
        for func_key, node_ids in self.icfg.functions.items():
            for node_id in list(node_ids):
                node = self.icfg.nodes.get(node_id)
                if not node or not node.is_reentrancy_sink():
                    continue
                for window in self.extract_window_for_call(node_id):
                    windows[window.window_id] = window
        self.mismatch_windows = windows
        return windows

    def extract_window_for_call(self, call_node_id: int) -> List[MismatchWindow]:
        node = self.icfg.nodes.get(call_node_id)
        if not node:
            return []

        ordered = self.icfg.get_function_nodes(node.function_key)
        if call_node_id not in ordered:
            return []

        windows: List[MismatchWindow] = []
        pre_write_nodes = self.find_state_writes_before(call_node_id, k=None)
        post_write_nodes = self.find_state_writes_after(call_node_id)

        if pre_write_nodes and post_write_nodes:
            post_use_nodes = self.find_state_uses_after(call_node_id, set(pre_write_nodes))
            relevant_states = set(pre_write_nodes) | set(post_write_nodes)
            start_node_id = min(pre_write_nodes.values())
            end_candidates = [
                node_id
                for state, node_id in {**post_use_nodes, **post_write_nodes}.items()
                if state in set(post_write_nodes)
            ]
            end_node_id = min(end_candidates) if end_candidates else ordered[-1]
            post_updated_states = set(post_write_nodes)

            windows.append(
                MismatchWindow(
                    window_id=f"window_{node.function_key}_{call_node_id}",
                    contract_name=node.contract_name,
                    function_name=node.function_name,
                    start_node_id=start_node_id,
                    external_call_node_id=call_node_id,
                    end_node_id=end_node_id,
                    pre_updated_states=relevant_states,
                    post_updated_states=post_updated_states,
                    queried_states=relevant_states,
                    severity="medium" if len(relevant_states) <= 1 else "high",
                    reason="State is updated before an external call and re-used or finalized after it",
                )
            )

        stale_window = self.extract_stale_cache_window_for_call(call_node_id, post_write_nodes)
        if stale_window:
            windows.append(stale_window)
        pre_external_window = self.extract_pre_external_window_for_call(call_node_id, pre_write_nodes, post_write_nodes)
        if pre_external_window:
            windows.append(pre_external_window)
        share_price_window = self.extract_share_price_window_for_call(call_node_id, pre_write_nodes)
        if share_price_window:
            windows.append(share_price_window)
        return windows

    def extract_stale_cache_window_for_call(
        self,
        call_node_id: int,
        post_write_nodes: Optional[Dict[str, int]] = None,
    ) -> Optional[MismatchWindow]:
        node = self.icfg.nodes.get(call_node_id)
        if not node or node.function_name == "constructor":
            return None
        if not self._is_mutating_external_call(node):
            return None

        ordered = self.icfg.get_function_nodes(node.function_key)
        if call_node_id not in ordered:
            return None

        post_write_nodes = post_write_nodes if post_write_nodes is not None else self.find_state_writes_after(call_node_id)
        if not post_write_nodes:
            return None

        readonly_states = self._states_read_by_public_readonly_queries()
        stale_states = set(post_write_nodes) & readonly_states
        if not stale_states:
            return None

        end_node_id = min(node_id for state, node_id in post_write_nodes.items() if state in stale_states)
        severity = "high" if any(self._is_cache_like_state(state) for state in stale_states) else "medium"
        return MismatchWindow(
            window_id=f"stale_window_{node.function_key}_{call_node_id}",
            contract_name=node.contract_name,
            function_name=node.function_name,
            start_node_id=call_node_id,
            external_call_node_id=call_node_id,
            end_node_id=end_node_id,
            pre_updated_states=set(),
            post_updated_states=stale_states,
            queried_states=stale_states,
            severity=severity,
            reason=(
                "Externally readable state remains stale during an external call "
                "and is only refreshed after the call returns"
            ),
            window_kind="stale_cache",
        )

    def extract_pre_external_window_for_call(
        self,
        call_node_id: int,
        pre_write_nodes: Optional[Dict[str, int]] = None,
        post_write_nodes: Optional[Dict[str, int]] = None,
    ) -> Optional[MismatchWindow]:
        node = self.icfg.nodes.get(call_node_id)
        if not node or node.function_name == "constructor":
            return None
        if not self._is_mutating_external_call(node):
            return None

        ordered = self.icfg.get_function_nodes(node.function_key)
        if call_node_id not in ordered:
            return None

        pre_write_nodes = pre_write_nodes if pre_write_nodes is not None else self.find_state_writes_before(call_node_id, k=None)
        if not pre_write_nodes:
            return None

        post_write_nodes = post_write_nodes if post_write_nodes is not None else self.find_state_writes_after(call_node_id)
        if post_write_nodes:
            return None

        readonly_states = self._states_read_by_public_readonly_queries()
        exposed_states = set(pre_write_nodes) & readonly_states
        exposed_states = {state for state in exposed_states if self._is_oracle_like_state(state)}
        if not exposed_states:
            return None

        start_node_id = min(node_id for state, node_id in pre_write_nodes.items() if state in exposed_states)
        return MismatchWindow(
            window_id=f"pre_external_window_{node.function_key}_{call_node_id}",
            contract_name=node.contract_name,
            function_name=node.function_name,
            start_node_id=start_node_id,
            external_call_node_id=call_node_id,
            end_node_id=call_node_id,
            pre_updated_states=exposed_states,
            post_updated_states=set(),
            queried_states=exposed_states,
            severity="high",
            reason=(
                "Externally readable oracle or accounting state is published before an external call "
                "whose off-contract effect has not completed"
            ),
            window_kind="pre_external_observable",
        )

    def extract_share_price_window_for_call(
        self,
        call_node_id: int,
        pre_write_nodes: Optional[Dict[str, int]] = None,
    ) -> Optional[MismatchWindow]:
        node = self.icfg.nodes.get(call_node_id)
        if not node or node.function_name == "constructor":
            return None
        if not self._is_mutating_external_call(node):
            return None

        ordered = self.icfg.get_function_nodes(node.function_key)
        if call_node_id not in ordered:
            return None

        pre_write_nodes = pre_write_nodes if pre_write_nodes is not None else self.find_state_writes_before(call_node_id, k=None)
        if not pre_write_nodes:
            return None

        share_writes = {
            state: node_id
            for state, node_id in pre_write_nodes.items()
            if self._is_share_accounting_state(state)
        }
        if not share_writes:
            return None

        exposed_states: Set[str] = set()
        for reads in self._share_price_query_reads().values():
            exposed_states.update(set(share_writes) & reads)
        if not exposed_states:
            return None

        start_node_id = min(node_id for state, node_id in share_writes.items() if state in exposed_states)
        return MismatchWindow(
            window_id=f"share_price_window_{node.function_key}_{call_node_id}",
            contract_name=node.contract_name,
            function_name=node.function_name,
            start_node_id=start_node_id,
            external_call_node_id=call_node_id,
            end_node_id=call_node_id,
            pre_updated_states=exposed_states,
            post_updated_states=set(),
            queried_states=exposed_states,
            severity="high",
            reason=(
                "Share/accounting state is updated before a mutating external call, "
                "and a public share-price query can observe the derived value"
            ),
            window_kind="share_price_observable",
        )

    def find_state_writes_before(self, call_node_id: int, k: Optional[int] = 5) -> Dict[str, int]:
        node = self.icfg.nodes.get(call_node_id)
        if not node:
            return {}

        ordered = self.icfg.get_function_nodes(node.function_key)
        call_index = ordered.index(call_node_id)
        result: Dict[str, int] = {}
        start_index = 0 if k is None else max(0, call_index - k)

        for candidate_id in reversed(ordered[start_index:call_index]):
            candidate = self.icfg.nodes.get(candidate_id)
            if not candidate:
                continue
            for state_var in self._node_effective_writes(candidate):
                result.setdefault(state_var, candidate_id)

        return result

    def find_state_uses_after(self, call_node_id: int, modified_states: Set[str]) -> Dict[str, int]:
        node = self.icfg.nodes.get(call_node_id)
        if not node:
            return {}

        ordered = self.icfg.get_function_nodes(node.function_key)
        call_index = ordered.index(call_node_id)
        result: Dict[str, int] = {}

        for candidate_id in ordered[call_index + 1 :]:
            candidate = self.icfg.nodes.get(candidate_id)
            if not candidate:
                continue
            touched = (candidate.reads | candidate.writes) & modified_states
            for state_var in touched:
                result.setdefault(state_var, candidate_id)

        return result

    def find_state_writes_after(
        self, call_node_id: int, modified_states: Optional[Set[str]] = None
    ) -> Dict[str, int]:
        node = self.icfg.nodes.get(call_node_id)
        if not node:
            return {}

        ordered = self.icfg.get_function_nodes(node.function_key)
        call_index = ordered.index(call_node_id)
        result: Dict[str, int] = {}

        for candidate_id in ordered[call_index + 1 :]:
            candidate = self.icfg.nodes.get(candidate_id)
            if not candidate:
                continue
            writes = candidate.writes if modified_states is None else candidate.writes & modified_states
            for state_var in writes:
                result.setdefault(state_var, candidate_id)

        return result

    def _states_read_by_public_readonly_queries(self) -> Set[str]:
        states: Set[str] = set()
        for func_key, meta in self.icfg.function_meta.items():
            if not meta.get("readonly"):
                continue
            visibility = str(meta.get("visibility") or "")
            if visibility and visibility not in {"public", "external"}:
                continue
            reads, _ = self.icfg.get_function_state_access(func_key)
            states.update(reads)
        return states

    def _share_price_query_reads(self) -> Dict[str, Set[str]]:
        result: Dict[str, Set[str]] = {}
        for func_key, meta in self.icfg.function_meta.items():
            if not meta.get("readonly"):
                continue
            visibility = str(meta.get("visibility") or "")
            if visibility and visibility not in {"public", "external"}:
                continue
            if not self._is_share_price_query_function(func_key):
                continue
            reads = self._function_effective_reads(func_key)
            if reads:
                result[func_key] = reads
        return result

    def _is_cache_like_state(self, state: str) -> bool:
        lowered = state.lower()
        return any(keyword in lowered for keyword in ("cache", "cached", "price", "rate", "total"))

    def _is_oracle_like_state(self, state: str) -> bool:
        lowered = state.lower()
        return any(
            keyword in lowered
            for keyword in (
                "cache",
                "cached",
                "price",
                "rate",
                "index",
            )
        )

    def _is_share_accounting_state(self, state: str) -> bool:
        lowered = state.lower()
        return any(keyword in lowered for keyword in SHARE_ACCOUNTING_STATE_HINTS)

    def _is_share_price_query_function(self, func_key: str) -> bool:
        function_name = func_key.rsplit(".", 1)[-1].lower()
        return any(keyword in function_name for keyword in SHARE_PRICE_QUERY_HINTS)

    def _node_effective_reads(self, node: Any) -> Set[str]:
        reads = set(getattr(node, "reads", set()) or set())
        for target in getattr(node, "call_targets", None) or []:
            if not self._should_inline_state_access(target, allow_readonly=True):
                continue
            target_reads, _ = self.icfg.get_function_state_access(target)
            reads.update(target_reads)
        return reads

    def _node_effective_writes(self, node: Any) -> Set[str]:
        writes = set(getattr(node, "writes", set()) or set())
        for target in getattr(node, "call_targets", None) or []:
            if not self._should_inline_state_access(target, allow_readonly=False):
                continue
            _, target_writes = self.icfg.get_function_state_access(target)
            writes.update(target_writes)
        return writes

    def _function_effective_reads(
        self,
        func_key: str,
        seen: Optional[Set[str]] = None,
        depth: int = 4,
    ) -> Set[str]:
        if depth < 0:
            return set()
        seen = seen or set()
        if func_key in seen:
            return set()
        seen.add(func_key)

        reads, _ = self.icfg.get_function_state_access(func_key)
        result = set(reads)
        for node_id in self.icfg.get_function_nodes(func_key):
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            result.update(getattr(node, "reads", set()) or set())
            for target in getattr(node, "call_targets", None) or []:
                if not self._should_inline_state_access(target, allow_readonly=True):
                    continue
                result.update(self._function_effective_reads(target, seen=set(seen), depth=depth - 1))
        return result

    def _should_inline_state_access(self, target: str, allow_readonly: bool) -> bool:
        if self.ablation_no_state_access_propagation:
            return False
        meta = self.icfg.function_meta.get(target, {})
        if not meta:
            return False
        visibility = str(meta.get("visibility") or "")
        if visibility in {"internal", "private"}:
            return True
        return bool(allow_readonly and meta.get("readonly"))

    def _is_mutating_external_call(self, node: Any) -> bool:
        if getattr(node, "call_type", "") in {"low_level_call", "delegatecall"}:
            return True
        call_targets = getattr(node, "call_targets", None) or []
        if not call_targets:
            return bool(getattr(node, "is_reentrancy_sink", lambda: False)())
        for target in call_targets:
            meta = self.icfg.function_meta.get(target, {})
            if not meta:
                return True
            if not meta.get("readonly"):
                return True
        return False

    def get_mismatch_window(self, window_id: str) -> Optional[MismatchWindow]:
        return self.mismatch_windows.get(window_id)

    def find_windows_by_call(self, call_node_id: int) -> List[MismatchWindow]:
        return [
            window
            for window in self.mismatch_windows.values()
            if window.external_call_node_id == call_node_id
        ]
