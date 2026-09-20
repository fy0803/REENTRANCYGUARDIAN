#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import sys
from typing import Any, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.path_feasibility import PathConstraintResult, PathFeasibilityChecker
from analysis.implicit_state import (
    CONTRACT_BALANCE_STATE,
    function_access_with_implicit_state,
    has_post_call_balance_dependency,
)
from models import CCRCandidate, RORCandidate


class Validator:
    """Validate CCR/ROR candidates against graph reachability and state overlap."""

    def __init__(
        self,
        icfg_builder: Any,
        lock_analyzer: Any,
        taint_engine: Any,
        path_timeout_ms: int = 1500,
        ccr_state_limit: Optional[int] = None,
        ablation_no_state_conflict: bool = False,
        ablation_no_lock_context: bool = False,
        ablation_no_path_constraints: bool = False,
        ablation_no_ror_propagation: bool = False,
        ablation_no_ror_sensitive_sink: bool = False,
        ablation_no_state_access_propagation: bool = False,
        ablation_explicit_state_conflict_only: bool = False,
    ):
        self.icfg = icfg_builder
        self.lock = lock_analyzer
        self.taint = taint_engine
        self.sink_rules = getattr(taint_engine, "sink_rules", None)
        self.path_solver = PathFeasibilityChecker(icfg_builder, timeout_ms=path_timeout_ms)
        self.ccr_state_limit = ccr_state_limit if ccr_state_limit and ccr_state_limit > 0 else None
        self.ablation_no_state_conflict = ablation_no_state_conflict
        self.ablation_no_lock_context = ablation_no_lock_context
        self.ablation_no_path_constraints = ablation_no_path_constraints
        self.ablation_no_ror_propagation = ablation_no_ror_propagation
        self.ablation_no_ror_sensitive_sink = ablation_no_ror_sensitive_sink
        self.ablation_no_state_access_propagation = ablation_no_state_access_propagation
        self.ablation_explicit_state_conflict_only = ablation_explicit_state_conflict_only

    def validate_ccr(self, candidate: CCRCandidate) -> Tuple[bool, str]:
        if not self._check_ccr_path_reachability(candidate):
            return False, "Path not reachable"
        if not self.ablation_no_path_constraints and not self._check_path_feasibility(candidate.path_node_ids).feasible:
            return False, "Path constraints are unsatisfiable"
        if not self.ablation_no_state_conflict and not self._check_state_conflict(candidate):
            return False, "No real state conflict"
        if not self._check_impact_propagation(candidate):
            return False, "Impact not propagated to sensitive logic"
        if not self.ablation_no_lock_context and candidate.lock_blocked:
            return False, "Protected by lock"
        return True, "Valid CCR candidate"

    def _check_ccr_path_reachability(self, candidate: CCRCandidate) -> bool:
        path = candidate.path_node_ids
        if self._check_path_reachability(path):
            return True
        if candidate.callback_kind != "classic" or not path or len(path) != 2:
            return False

        external_node = self.icfg.nodes.get(candidate.external_call_node) if self.icfg else None
        callback_func = f"{candidate.target_contract}.{candidate.callback_entry_function}"
        callback_entry = self.icfg.get_function_entry(callback_func) if self.icfg else None
        return bool(
            external_node
            and external_node.is_reentrancy_sink()
            and path[0] == candidate.external_call_node
            and path[1] == callback_entry
            and external_node.contract_name == candidate.target_contract
        )

    def validate_ror(self, candidate: RORCandidate) -> Tuple[bool, str]:
        if not self._check_mismatch_validity(candidate):
            return False, "Invalid mismatch window"
        if not self._check_pollution_relation(candidate):
            return False, "Query not polluted by mismatch states"
        if not self.ablation_no_ror_sensitive_sink and not self._check_propagation_to_sink(candidate):
            return False, "Pollution not propagated to sink"
        tracked_vars = set(candidate.tainted_query_vars) | set(candidate.tainted_sink_vars)
        path_result = (
            PathConstraintResult(feasible=True, tracked_vars=tracked_vars)
            if self.ablation_no_path_constraints
            else self._check_path_feasibility(candidate.propagation_path, tracked_vars=tracked_vars)
        )
        candidate.tainted_constraint_vars = set(path_result.tainted_constraint_vars)
        if not path_result.feasible:
            return False, "Propagation path constraints are unsatisfiable"
        if candidate.mitigated:
            return False, f"Mitigated: {candidate.mitigation_reason}"
        return True, "Valid ROR candidate"

    def _check_path_reachability(self, path: List[int]) -> bool:
        if not path or not all(isinstance(node_id, int) for node_id in path):
            return False
        if not (self.icfg and hasattr(self.icfg, "nodes") and self.icfg.nodes):
            return True
        if not all(node_id in self.icfg.nodes for node_id in path):
            return False
        if len(path) == 1:
            return True
        for current, nxt in zip(path, path[1:]):
            if nxt not in self.icfg.get_successors(current, include_semantic=True):
                return False
        return True

    def _check_path_feasibility(
        self,
        path: List[int],
        tracked_vars: Optional[Set[str]] = None,
    ) -> PathConstraintResult:
        return self.path_solver.analyze_path(path, tracked_vars=tracked_vars)

    def _check_state_conflict(self, ccr: CCRCandidate) -> bool:
        if not ccr.overlap_states or ccr.external_call_node < 0:
            return False
        external_node = self.icfg.nodes.get(ccr.external_call_node) if self.icfg else None
        if not external_node:
            return False

        func_key = f"{ccr.source_contract}.{ccr.entry_function}"
        entry_id = self.icfg.get_function_entry(func_key)
        if entry_id is None:
            return False

        state_slice = self.icfg.get_execution_state_slice(
            func_key,
            max_states=self.ccr_state_limit,
        )
        call_states = {state for state in state_slice if state[0] == ccr.external_call_node}
        if not call_states:
            return False

        pre_writes: Set[str] = set()
        post_access: Set[str] = set()
        post_writes: Set[str] = set()

        post_states = self.icfg.get_reachable_execution_states(
            call_states,
            max_depth=128,
            max_states=self.ccr_state_limit,
        )
        reachability_cache: dict[tuple[int, tuple[int, ...]], set[tuple[int, tuple[int, ...]]]] = {}

        for state in state_slice:
            node_id, _ = state
            if node_id == ccr.external_call_node:
                continue
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            reachable = reachability_cache.setdefault(
                state,
                self.icfg.get_reachable_execution_states(
                    {state},
                    max_depth=128,
                    max_states=self.ccr_state_limit,
                ),
            )
            if any(call_state in reachable for call_state in call_states):
                pre_writes.update(node.writes)

        for node_id, _ in post_states:
            if node_id == ccr.external_call_node:
                continue
            node = self.icfg.nodes.get(node_id)
            if node:
                post_access.update(node.reads | node.writes)
                post_writes.update(node.writes)

        overlap = pre_writes & post_access
        if overlap:
            return bool(ccr.overlap_states & overlap)
        if self.ablation_explicit_state_conflict_only:
            return False
        if post_writes:
            return bool(ccr.overlap_states & post_writes)
        if CONTRACT_BALANCE_STATE in ccr.overlap_states:
            return has_post_call_balance_dependency(self.icfg, post_states)
        return False

    def _check_impact_propagation(self, ccr: CCRCandidate) -> bool:
        if not (ccr.callback_entry_function and ccr.overlap_states):
            return False
        callback_func = f"{ccr.target_contract}.{ccr.callback_entry_function}"
        callback_entry = self.icfg.get_function_entry(callback_func)
        if callback_entry is None:
            return False
        if not self.icfg.path_exists(
            ccr.external_call_node,
            callback_entry,
            semantic_types={"callback", "callback_cross_contract", "alias", "delegatecall"},
        ) and not self._is_virtual_classic_callback(ccr, callback_entry):
            return False
        return self._function_reaches_state_access(callback_func, ccr.overlap_states)

    def _is_virtual_classic_callback(self, ccr: CCRCandidate, callback_entry: int) -> bool:
        if ccr.callback_kind != "classic":
            return False
        external_node = self.icfg.nodes.get(ccr.external_call_node) if self.icfg else None
        if not external_node or not external_node.is_reentrancy_sink():
            return False
        return (
            external_node.contract_name == ccr.target_contract
            and callback_entry == self.icfg.get_function_entry(
                f"{ccr.target_contract}.{ccr.callback_entry_function}"
            )
        )

    def _check_mismatch_validity(self, ror: RORCandidate) -> bool:
        if not ror.window_id:
            return False
        if min(ror.start_node_id, ror.external_call_node_id, ror.end_node_id) < 0:
            return False
        if not (ror.start_node_id <= ror.external_call_node_id <= ror.end_node_id):
            return False
        if not ror.overlap_states:
            return False
        query_meta = self.icfg.function_meta.get(ror.query_function, {})
        if getattr(ror, "external_sink", False):
            external_node = self.icfg.nodes.get(ror.external_call_node_id)
            return bool(query_meta.get("readonly") and external_node and external_node.is_reentrancy_sink())
        sink_meta = self.icfg.function_meta.get(ror.sink_function or "", {})
        return bool(query_meta.get("readonly")) and not bool(sink_meta.get("readonly"))

    def _check_pollution_relation(self, ror: RORCandidate) -> bool:
        if not ror.overlap_states:
            return False
        query_entry = self.icfg.get_function_entry(ror.query_function)
        if query_entry is None:
            return False
        reads = self._function_effective_reads(ror.query_function)
        if not (ror.overlap_states & reads):
            return False
        return self._function_reaches_state_access(ror.query_function, ror.overlap_states, read_only=True)

    def _check_propagation_to_sink(self, ror: RORCandidate) -> bool:
        if getattr(ror, "external_sink", False):
            external_node = self.icfg.nodes.get(ror.external_call_node_id)
            return bool(
                external_node
                and external_node.is_reentrancy_sink()
                and ror.query_function
                and ror.overlap_states
            )
        if self.ablation_no_ror_propagation:
            return bool(ror.sink_function and ror.sink_node_ids and ror.query_function and ror.overlap_states)
        if not ror.sink_function or not ror.sink_node_ids or not ror.propagation_path:
            return False
        if not self._check_path_reachability(ror.propagation_path):
            return False
        if ror.propagation_path[-1] not in ror.sink_node_ids:
            return False

        query_entry = self.icfg.get_function_entry(ror.query_function)
        if query_entry is None or query_entry not in ror.propagation_path:
            return False

        if not any(
            self.icfg.nodes.get(node_id) and self.icfg.nodes[node_id].function_key == ror.sink_function
            for node_id in ror.propagation_path
        ):
            return False

        sink_node = self.icfg.nodes.get(ror.propagation_path[-1])
        if not sink_node:
            return False
        if not ror.tainted_query_vars or not ror.tainted_sink_vars:
            return False

        sink_consumed = ror.tainted_consumed_by_node.get(ror.propagation_path[-1], set())
        if not sink_consumed or not (sink_consumed & ror.tainted_sink_vars):
            return False

        if self.sink_rules:
            return bool(
                self.sink_rules.is_critical_operation(sink_node)
                or sink_node.writes
                or sink_node.is_reentrancy_sink()
            )
        return bool(sink_node.writes or sink_node.is_reentrancy_sink())

    def _function_reaches_state_access(
        self,
        func_key: str,
        states: Set[str],
        read_only: bool = False,
    ) -> bool:
        entry = self.icfg.get_function_entry(func_key)
        if entry is None:
            return False
        if CONTRACT_BALANCE_STATE in states:
            if CONTRACT_BALANCE_STATE in function_access_with_implicit_state(self.icfg, func_key):
                return True
        for node_id in self.icfg.get_function_nodes(func_key):
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            if read_only:
                accessed = self._node_effective_reads(node)
            else:
                accessed = self._node_effective_reads(node) | self._node_effective_writes(node)
            if not (accessed & states):
                continue
            if self.icfg.path_exists(entry, node_id, include_semantic=False):
                return True
        return False

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
