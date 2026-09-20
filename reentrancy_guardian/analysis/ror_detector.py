#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Set

from models import MismatchWindow, RORCandidate

EXTERNAL_READONLY_CONSUMER = "__external_readonly_consumer__"
EXTERNAL_CONSUMER_WINDOW_KINDS = {
    "stale_cache",
    "pre_external_observable",
    "share_price_observable",
}
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


class RORDetector:
    """Detect read-only reentrancy candidates from mismatch windows."""

    def __init__(
        self,
        icfg_builder: Any,
        mismatch_detector: Any,
        taint_engine: Any,
        *,
        ablation_no_mismatch_window: bool = False,
        ablation_no_propagation: bool = False,
        ablation_no_state_access_propagation: bool = False,
    ):
        self.icfg = icfg_builder
        self.mismatch = mismatch_detector
        self.taint = taint_engine
        self.ablation_no_mismatch_window = ablation_no_mismatch_window
        self.ablation_no_propagation = ablation_no_propagation
        self.ablation_no_state_access_propagation = ablation_no_state_access_propagation

    def detect(self) -> List[RORCandidate]:
        if self.ablation_no_mismatch_window:
            return []

        windows = list((self.mismatch.mismatch_windows or self.mismatch.detect_windows()).values())
        if not windows:
            return []

        query_functions = self._collect_query_functions()
        candidates: List[RORCandidate] = []

        for window in windows:
            for query_func, query_reads in query_functions.items():
                if getattr(window, "window_kind", "") == "share_price_observable":
                    if not self._is_share_price_query_function(query_func):
                        continue
                overlap = (window.pre_updated_states | window.post_updated_states) & query_reads
                if not overlap:
                    continue

                for sink_func, sink_nodes in self.find_sink_functions(query_func, window).items():
                    candidate = self.create_candidate(window, query_func, sink_func, overlap)
                    candidate.sink_node_ids = sink_nodes
                    candidate.propagation_path = self.analyze_propagation(candidate)
                    candidates.append(candidate)

                if getattr(window, "window_kind", "") in EXTERNAL_CONSUMER_WINDOW_KINDS:
                    candidates.append(self.create_external_consumer_candidate(window, query_func, overlap))

        return self._dedupe(candidates)

    def collect_mismatch_windows(self) -> List[MismatchWindow]:
        return list((self.mismatch.mismatch_windows or self.mismatch.detect_windows()).values())

    def find_query_functions(self, window: MismatchWindow) -> Dict[str, Set[str]]:
        query_functions: Dict[str, Set[str]] = {}
        window_states = window.pre_updated_states | window.post_updated_states
        for func_key, reads in self._collect_query_functions().items():
            overlap = reads & window_states
            if overlap:
                query_functions[func_key] = overlap
        return query_functions

    def find_sink_functions(self, query_func: str, window: MismatchWindow = None) -> Dict[str, List[int]]:
        query_entry = self.icfg.get_function_entry(query_func)
        if query_entry is None:
            return {}

        sinks: Dict[str, List[int]] = {}
        for src, dst in self.icfg.edges_call:
            if dst != query_entry:
                continue
            caller = self.icfg.nodes.get(src)
            if not caller:
                continue
            sink_func = caller.function_key
            meta = self.icfg.function_meta.get(sink_func, {})
            if meta.get("readonly"):
                continue
            if window and sink_func == f"{window.contract_name}.{window.function_name}" and src <= window.external_call_node_id:
                continue
            sink_nodes = self._critical_nodes_in_function(sink_func, after_node_id=src)
            if not sink_nodes:
                sink_nodes = [src]
            sinks[sink_func] = sink_nodes
        return sinks

    def form_candidates(self, window: MismatchWindow, query_func: str, sink_funcs: List[str]) -> List[RORCandidate]:
        query_states = self.find_query_functions(window).get(query_func, set())
        return [self.create_candidate(window, query_func, sink_func, query_states) for sink_func in sink_funcs]

    def verify_candidate(self, candidate: RORCandidate) -> bool:
        return bool(candidate.window_id and candidate.query_function and candidate.sink_function and candidate.overlap_states)

    def analyze_propagation(self, candidate: RORCandidate) -> List[int]:
        if self.ablation_no_propagation:
            return []

        if not candidate.sink_node_ids:
            return []

        source_node_ids = self._window_source_nodes(candidate)
        if not source_node_ids:
            return []

        self.taint.reset()
        for overlap_state in candidate.overlap_states:
            self.taint.mark_taint_source(overlap_state)

        propagation_path = self.taint.find_readonly_taint_path(
            source_node_ids=source_node_ids,
            source_states=candidate.overlap_states,
            query_function=candidate.query_function,
            sink_function=candidate.sink_function or "",
            sink_node_ids=candidate.sink_node_ids,
        )
        evidence = self.taint.get_latest_readonly_evidence()
        candidate.tainted_query_vars = set(evidence.query_result_vars)
        candidate.tainted_sink_vars = set(evidence.sink_consumed_taints)
        candidate.tainted_consumed_by_node = {
            node_id: set(values) for node_id, values in evidence.consumed_taints_by_node.items()
        }
        return propagation_path

    def check_mitigation(self, candidate: RORCandidate):
        return False, ""

    def create_candidate(
        self,
        window: MismatchWindow,
        query_func: str,
        sink_func: str,
        overlap_states: Set[str],
    ) -> RORCandidate:
        return RORCandidate(
            candidate_id=f"ror_{window.window_id}_{query_func}_{sink_func}",
            contract_name=window.contract_name,
            window_function=window.function_name,
            window_id=window.window_id,
            start_node_id=window.start_node_id,
            external_call_node_id=window.external_call_node_id,
            end_node_id=window.end_node_id,
            query_function=query_func,
            query_return_states=self._collect_query_functions().get(query_func, set()),
            sink_function=sink_func,
            overlap_states=overlap_states,
            reason=(
                f"Window {window.window_id} leaves states {sorted(overlap_states)} inconsistent, "
                f"query {query_func} reads them, and sink {sink_func} consumes the query result"
            ),
            confidence=0.65,
        )

    def create_external_consumer_candidate(
        self,
        window: MismatchWindow,
        query_func: str,
        overlap_states: Set[str],
    ) -> RORCandidate:
        if getattr(window, "window_kind", "") == "share_price_observable":
            reason = (
                f"Window {window.window_id} publishes share/accounting states {sorted(overlap_states)} "
                f"before a mutating external call; query {query_func} can expose the derived "
                "share-price value to an external protocol or caller"
            )
        else:
            reason = (
                f"Window {window.window_id} leaves externally readable states {sorted(overlap_states)} "
                f"stale during an external call; query {query_func} can expose the stale value "
                "to an external protocol or caller"
            )
        return RORCandidate(
            candidate_id=f"ror_{window.window_id}_{query_func}_{EXTERNAL_READONLY_CONSUMER}",
            contract_name=window.contract_name,
            window_function=window.function_name,
            window_id=window.window_id,
            start_node_id=window.start_node_id,
            external_call_node_id=window.external_call_node_id,
            end_node_id=window.end_node_id,
            query_function=query_func,
            query_return_states=self._collect_query_functions().get(query_func, set()),
            sink_function=EXTERNAL_READONLY_CONSUMER,
            sink_node_ids=[window.external_call_node_id],
            overlap_states=overlap_states,
            propagation_path=[window.external_call_node_id],
            tainted_query_vars=set(overlap_states),
            tainted_sink_vars={EXTERNAL_READONLY_CONSUMER},
            tainted_consumed_by_node={window.external_call_node_id: set(overlap_states)},
            reason=reason,
            confidence=0.7,
            external_sink=True,
        )

    def _collect_query_functions(self) -> Dict[str, Set[str]]:
        result: Dict[str, Set[str]] = {}
        for func_key, meta in self.icfg.function_meta.items():
            if not meta.get("readonly"):
                continue
            reads = self._function_effective_reads(func_key)
            if reads:
                result[func_key] = reads
        return result

    def _function_effective_reads(
        self,
        func_key: str,
        seen: Set[str] = None,
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
                if not self._should_inline_state_access(target):
                    continue
                result.update(self._function_effective_reads(target, seen=set(seen), depth=depth - 1))
        return result

    def _should_inline_state_access(self, target: str) -> bool:
        if self.ablation_no_state_access_propagation:
            return False
        meta = self.icfg.function_meta.get(target, {})
        if not meta:
            return False
        visibility = str(meta.get("visibility") or "")
        return visibility in {"internal", "private"} or bool(meta.get("readonly"))

    def _is_share_price_query_function(self, func_key: str) -> bool:
        function_name = func_key.rsplit(".", 1)[-1].lower()
        return any(keyword in function_name for keyword in SHARE_PRICE_QUERY_HINTS)

    def _critical_nodes_in_function(self, func_key: str, after_node_id: int = 0) -> List[int]:
        result: List[int] = []
        for node_id in self.icfg.get_function_nodes(func_key):
            if node_id <= after_node_id:
                continue
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            if self.taint.sink_rules.is_critical_operation(node) or node.writes or node.is_reentrancy_sink():
                result.append(node_id)
        return result

    def _find_query_callsites(self, query_func: str, sink_func: str) -> List[int]:
        query_entry = self.icfg.get_function_entry(query_func)
        if query_entry is None:
            return []
        return sorted(
            src
            for src, dst in self.icfg.edges_call
            if dst == query_entry and self.icfg.nodes.get(src) and self.icfg.nodes[src].function_key == sink_func
        )

    def _merge_paths(self, left: List[int], right: List[int]) -> List[int]:
        merged: List[int] = []
        for node_id in left + right:
            if not merged or merged[-1] != node_id:
                merged.append(node_id)
        return merged

    def _window_source_nodes(self, candidate: RORCandidate) -> List[int]:
        func_key = f"{candidate.contract_name}.{candidate.window_function}"
        result: List[int] = []
        for node_id in self.icfg.get_function_nodes(func_key):
            if node_id < candidate.start_node_id or node_id > candidate.external_call_node_id:
                continue
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            if self._node_effective_writes(node) & candidate.overlap_states:
                result.append(node_id)
        return result or [candidate.start_node_id]

    def _node_effective_writes(self, node: Any) -> Set[str]:
        writes = set(getattr(node, "writes", set()) or set())
        if self.ablation_no_state_access_propagation:
            return writes
        for target in getattr(node, "call_targets", None) or []:
            meta = self.icfg.function_meta.get(target, {})
            if str(meta.get("visibility") or "") not in {"internal", "private"}:
                continue
            _, target_writes = self.icfg.get_function_state_access(target)
            writes.update(target_writes)
        return writes

    def _dedupe(self, candidates: List[RORCandidate]) -> List[RORCandidate]:
        deduped: Dict[str, RORCandidate] = {}
        for candidate in candidates:
            if candidate.external_sink:
                key = (
                    candidate.contract_name,
                    candidate.window_function,
                    candidate.query_function,
                    candidate.sink_function,
                    tuple(sorted(candidate.overlap_states)),
                )
            else:
                key = (
                    candidate.window_id,
                    candidate.query_function,
                    candidate.sink_function,
                    tuple(sorted(candidate.overlap_states)),
                )
            deduped.setdefault(str(key), candidate)
        return list(deduped.values())
