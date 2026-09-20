#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections import defaultdict, deque
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass
class IRInstruction:
    kind: str
    defs: Set[str] = field(default_factory=set)
    uses: Set[str] = field(default_factory=set)
    returns: Set[str] = field(default_factory=set)


@dataclass
class NodeIRSummary:
    node_id: int
    instructions: List[IRInstruction] = field(default_factory=list)
    defined_vars: Set[str] = field(default_factory=set)
    used_vars: Set[str] = field(default_factory=set)
    returned_vars: Set[str] = field(default_factory=set)
    call_result_vars: Set[str] = field(default_factory=set)


@dataclass
class PathTaintResult:
    node_in: Dict[int, Set[str]] = field(default_factory=dict)
    node_out: Dict[int, Set[str]] = field(default_factory=dict)
    final_taints: Set[str] = field(default_factory=set)
    return_taints: Set[str] = field(default_factory=set)
    consumed_taints: Dict[int, Set[str]] = field(default_factory=dict)


@dataclass
class ReadonlyTaintEvidence:
    path: List[int] = field(default_factory=list)
    query_return_taints: Set[str] = field(default_factory=set)
    query_result_vars: Set[str] = field(default_factory=set)
    sink_consumed_taints: Set[str] = field(default_factory=set)
    consumed_taints_by_node: Dict[int, Set[str]] = field(default_factory=dict)
    sink_node_id: Optional[int] = None


class TaintAnalysis:
    """Basic taint analysis state."""

    def __init__(self):
        self.tainted_vars: Set[Any] = set()
        self.taint_sources: Set[Any] = set()
        self.taint_sinks: Set[Any] = set()
        self.taint_flow: List[Tuple[Any, Any]] = []

    def mark_source(self, var: Any):
        self.tainted_vars.add(var)
        self.taint_sources.add(var)

    def mark_sink(self, var: Any):
        self.taint_sinks.add(var)

    def is_tainted(self, var: Any) -> bool:
        return var in self.tainted_vars


class EnhancedTaintAnalysis(TaintAnalysis):
    """Interprocedural taint analysis state with SSA-like dependencies."""

    def __init__(self, icfg_builder: Any, sink_rules: Any):
        super().__init__()
        self.icfg = icfg_builder
        self.sink_rules = sink_rules
        self.taint_graph: Dict[Any, Set[Any]] = defaultdict(set)
        self.interprocedural_taint: Set[Any] = set()
        self.return_taint: Dict[str, Set[Any]] = {}
        self.param_taint: Dict[str, List[Set[Any]]] = {}
        self.node_taint_in: Dict[int, Set[str]] = defaultdict(set)
        self.node_taint_out: Dict[int, Set[str]] = defaultdict(set)
        self.node_dependencies: Dict[int, Set[int]] = defaultdict(set)

    def propagate_assignment(self, src_var: Any, dst_var: Any):
        if self.is_tainted(src_var):
            self.tainted_vars.add(dst_var)
            self.taint_graph[dst_var].add(src_var)
            self.taint_flow.append((src_var, dst_var))

    def propagate_parameter(self, function: str, param_idx: int, var: Any):
        if function not in self.param_taint:
            self.param_taint[function] = []
        if param_idx >= len(self.param_taint[function]):
            self.param_taint[function].extend(set() for _ in range(param_idx - len(self.param_taint[function]) + 1))
        if self.is_tainted(var):
            self.param_taint[function][param_idx].add(var)
            self.taint_flow.append((var, f"{function}::param::{param_idx}"))

    def propagate_return(self, function: str, var: Any):
        if function not in self.return_taint:
            self.return_taint[function] = set()
        if self.is_tainted(var):
            self.return_taint[function].add(var)
            self.taint_flow.append((var, f"{function}::return"))

    def propagate_state_to_local(self, state_var: str, local_var: str):
        if self.is_tainted(state_var):
            self.tainted_vars.add(local_var)
            self.taint_graph[local_var].add(state_var)
            self.taint_flow.append((state_var, local_var))

    def propagate_cross_contract(self, src_contract: str, dst_contract: str, var: Any):
        if self.is_tainted(var):
            self.interprocedural_taint.add(var)
            self.taint_flow.append((var, f"{src_contract}->{dst_contract}"))

    def mark_node_taint(self, node_id: int, taints: Set[str], predecessor: Optional[int] = None):
        self.record_node_state(node_id, taints, taints, predecessor=predecessor)

    def record_node_state(
        self,
        node_id: int,
        taints_in: Set[str],
        taints_out: Set[str],
        predecessor: Optional[int] = None,
    ):
        if not taints_in and not taints_out:
            return
        if predecessor is not None:
            self.node_dependencies[node_id].add(predecessor)
        self.node_taint_in[node_id].update(taints_in)
        self.node_taint_out[node_id].update(taints_out)
        for taint in taints_out:
            self.mark_source(taint)

    def add_flow(self, src_var: Any, dst_var: Any):
        self.tainted_vars.add(dst_var)
        self.taint_graph[dst_var].add(src_var)
        self.taint_flow.append((src_var, dst_var))

    def track_path(self, source_var: Any, sink_var: Any) -> Optional[List[Any]]:
        if source_var not in self.tainted_vars or sink_var not in self.tainted_vars:
            return None

        queue = deque([(source_var, [source_var])])
        visited = {source_var}
        while queue:
            current, path = queue.popleft()
            if current == sink_var:
                return path
            for var, depset in self.taint_graph.items():
                if current in depset and var not in visited:
                    visited.add(var)
                    queue.append((var, path + [var]))
        return None

    def get_taint_summary(self) -> Dict[str, Any]:
        return {
            "sources": list(self.taint_sources),
            "sinks": list(self.taint_sinks),
            "tainted_vars": list(self.tainted_vars),
            "total_taint_paths": len(self.taint_flow),
            "node_taint_in": {node_id: sorted(values) for node_id, values in self.node_taint_in.items()},
            "node_taint_out": {node_id: sorted(values) for node_id, values in self.node_taint_out.items()},
        }


class TaintEngine:
    """Taint engine backed by SlithIR-like def-use propagation on the SE-ICFG."""

    def __init__(self, icfg_builder: Any, sink_rules: Any):
        self.icfg = icfg_builder
        self.sink_rules = sink_rules
        self.analysis = EnhancedTaintAnalysis(icfg_builder, sink_rules)
        self.latest_readonly_evidence = ReadonlyTaintEvidence()
        self._summary_cache: Dict[int, NodeIRSummary] = {}
        self._symbol_pattern = re.compile(
            r"msg\.sender|msg\.value|tx\.origin|block\.timestamp|block\.number|(?:TMP|REF|TUPLE)_\d+|[A-Za-z_][A-Za-z0-9_]*"
        )
        self._ignored_symbols = {
            "and",
            "arguments",
            "assert",
            "bool",
            "bytes",
            "call",
            "delegatecall",
            "dest",
            "false",
            "function",
            "high_level_call",
            "index",
            "internal_call",
            "low_level_call",
            "none",
            "or",
            "require",
            "solidity_call",
            "staticcall",
            "string",
            "true",
            "value",
        }

    def reset(self):
        self.analysis = EnhancedTaintAnalysis(self.icfg, self.sink_rules)
        self.latest_readonly_evidence = ReadonlyTaintEvidence()

    def mark_taint_source(self, var: Any):
        self.analysis.mark_source(var)

    def mark_taint_sink(self, var: Any):
        self.analysis.mark_sink(var)

    def propagate_taint(self, operation: Dict[str, Any]):
        op_type = operation.get("type")
        if op_type == "assignment":
            self.analysis.propagate_assignment(operation.get("src_var"), operation.get("dst_var"))
            return
        if op_type == "parameter":
            self.analysis.propagate_parameter(
                operation.get("function", ""),
                int(operation.get("param_idx", 0)),
                operation.get("var"),
            )
            return
        if op_type == "return":
            self.analysis.propagate_return(operation.get("function", ""), operation.get("var"))
            return
        if op_type == "state_load":
            self.analysis.propagate_state_to_local(
                operation.get("state_var"),
                operation.get("local_var"),
            )
            return
        if op_type == "cross_contract":
            self.analysis.propagate_cross_contract(
                operation.get("src_contract", ""),
                operation.get("dst_contract", ""),
                operation.get("var"),
            )

    def has_taint_path(self, source: Any, sink: Any) -> bool:
        return self.analysis.track_path(source, sink) is not None

    def get_taint_path(self, source: Any, sink: Any) -> Optional[List[Any]]:
        return self.analysis.track_path(source, sink)

    def find_readonly_taint_path(
        self,
        source_node_ids: Sequence[int],
        source_states: Set[str],
        query_function: str,
        sink_function: str,
        sink_node_ids: Sequence[int],
    ) -> List[int]:
        """
        Build a node-level taint path on the SE-ICFG using SlithIR-style def-use chains:
        source writer -> query entry/reader/return -> caller follow-up -> critical sink.
        """
        if not source_node_ids or not source_states or not sink_node_ids:
            return []

        query_entry = self.icfg.get_function_entry(query_function)
        if query_entry is None:
            return []

        query_reader_nodes = self._query_reader_nodes(query_function, source_states)
        if not query_reader_nodes:
            return []

        sink_callsites = self._find_query_callsites(query_function, sink_function)
        if not sink_callsites:
            return []

        best_source_path = self._find_best_source_to_query_path(source_node_ids, query_entry)
        if not best_source_path:
            return []

        query_reader_path = self._find_best_in_function_path(query_entry, query_reader_nodes)
        if not query_reader_path:
            return []

        query_exit_path = self._find_best_in_function_path(
            query_reader_path[-1],
            self.icfg.get_function_exits(query_function),
        )
        if not query_exit_path:
            query_exit_path = [query_reader_path[-1]]

        query_path = self._merge_paths(query_reader_path, query_exit_path)
        query_result = self._propagate_path(query_path, set(source_states))
        if not query_result.return_taints:
            return []

        for callsite in sink_callsites:
            followup = self.icfg.get_callsite_followup(callsite)
            if followup is None:
                continue

            query_result_vars = self._query_callsite_result_vars(callsite, query_result.return_taints)
            if not query_result_vars:
                continue

            for sink_node_id in sink_node_ids:
                sink_path = self._find_cfg_path(followup, sink_node_id)
                if not sink_path:
                    continue

                sink_result = self._propagate_path(
                    sink_path,
                    set(source_states) | set(query_result_vars),
                )
                if not self._sink_path_consumes_taint(sink_path, sink_node_id, sink_result):
                    continue

                full_path = self._merge_paths(best_source_path, query_path, sink_path)
                self.latest_readonly_evidence = ReadonlyTaintEvidence(
                    path=list(full_path),
                    query_return_taints=set(query_result.return_taints),
                    query_result_vars=set(query_result_vars),
                    sink_consumed_taints=set(sink_result.consumed_taints.get(sink_node_id, set())),
                    consumed_taints_by_node={
                        node_id: set(values) for node_id, values in sink_result.consumed_taints.items()
                    },
                    sink_node_id=sink_node_id,
                )
                self._record_full_path(best_source_path, source_states, query_result, sink_result, full_path)
                return full_path

        return []

    def get_latest_readonly_evidence(self) -> ReadonlyTaintEvidence:
        return ReadonlyTaintEvidence(
            path=list(self.latest_readonly_evidence.path),
            query_return_taints=set(self.latest_readonly_evidence.query_return_taints),
            query_result_vars=set(self.latest_readonly_evidence.query_result_vars),
            sink_consumed_taints=set(self.latest_readonly_evidence.sink_consumed_taints),
            consumed_taints_by_node={
                node_id: set(values)
                for node_id, values in self.latest_readonly_evidence.consumed_taints_by_node.items()
            },
            sink_node_id=self.latest_readonly_evidence.sink_node_id,
        )

    def _find_best_source_to_query_path(self, source_node_ids: Sequence[int], query_entry: int) -> List[int]:
        candidates: List[List[int]] = []
        for source_node_id in source_node_ids:
            path = self.icfg.find_path(
                source_node_id,
                query_entry,
                semantic_types={"readonly_dep"},
            )
            if path:
                candidates.append(path)
        if not candidates:
            return []
        return min(candidates, key=len)

    def _query_reader_nodes(self, query_function: str, source_states: Set[str]) -> List[int]:
        readers: List[int] = []
        for node_id in self.icfg.get_function_nodes(query_function):
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue
            if node.reads & source_states:
                readers.append(node_id)
        return readers

    def _find_best_in_function_path(self, start_node_id: int, target_node_ids: Sequence[int]) -> List[int]:
        candidates: List[List[int]] = []
        for target_node_id in target_node_ids:
            path = self._find_cfg_path(start_node_id, target_node_id)
            if path:
                candidates.append(path)
        if not candidates:
            return []
        return min(candidates, key=len)

    def _find_query_callsites(self, query_function: str, sink_function: str) -> List[int]:
        query_entry = self.icfg.get_function_entry(query_function)
        if query_entry is None:
            return []
        return sorted(
            src
            for src, dst in self.icfg.edges_call
            if dst == query_entry and self.icfg.nodes.get(src) and self.icfg.nodes[src].function_key == sink_function
        )

    def _find_cfg_path(self, start_node_id: int, end_node_id: int) -> List[int]:
        return self.icfg.find_path(
            start_node_id,
            end_node_id,
            include_semantic=False,
        )

    def _propagate_path(self, node_path: Sequence[int], initial_taints: Set[str]) -> PathTaintResult:
        result = PathTaintResult(final_taints=set(initial_taints))
        current_taints = set(initial_taints)

        for node_id in node_path:
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue

            result.node_in[node_id] = set(current_taints)
            summary = self._summarize_node(node_id)

            for instruction in summary.instructions:
                tainted_uses = instruction.uses & current_taints
                if instruction.kind == "return" and tainted_uses:
                    result.return_taints.update(tainted_uses)

                if tainted_uses:
                    for defined_var in instruction.defs:
                        if defined_var not in current_taints:
                            current_taints.add(defined_var)
                        for tainted_use in tainted_uses:
                            self.analysis.add_flow(tainted_use, defined_var)

                if instruction.kind == "index" and tainted_uses:
                    for defined_var in instruction.defs:
                        current_taints.add(defined_var)

            if node.reads & current_taints:
                current_taints.update(node.reads & current_taints)
            if node.writes & current_taints:
                current_taints.update(node.writes)

            consumed = summary.used_vars & current_taints
            if consumed:
                result.consumed_taints[node_id] = set(consumed)

            result.node_out[node_id] = set(current_taints)

        result.final_taints = set(current_taints)
        return result

    def _query_callsite_result_vars(self, callsite: int, query_return_taints: Set[str]) -> Set[str]:
        if not query_return_taints:
            return set()
        summary = self._summarize_node(callsite)
        if not summary.call_result_vars:
            return set()

        concrete_vars = {
            var for var in summary.call_result_vars if not self._is_temporary(var)
        }
        return concrete_vars or set(summary.call_result_vars)

    def _sink_path_consumes_taint(
        self,
        sink_path: Sequence[int],
        sink_node_id: int,
        result: PathTaintResult,
    ) -> bool:
        sink_node = self.icfg.nodes.get(sink_node_id)
        if not sink_node:
            return False
        consumed = result.consumed_taints.get(sink_node_id, set())
        if not consumed:
            return False
        return bool(
            consumed
            and (self.sink_rules.is_critical_operation(sink_node) or sink_node.writes or sink_node.is_reentrancy_sink())
        )

    def _record_full_path(
        self,
        source_path: Sequence[int],
        source_states: Set[str],
        query_result: PathTaintResult,
        sink_result: PathTaintResult,
        full_path: Sequence[int],
    ):
        predecessor: Optional[int] = None
        source_nodes = set(source_path)

        for node_id in full_path:
            if node_id in source_nodes:
                taints_in = set(source_states)
                taints_out = set(source_states)
            elif node_id in query_result.node_in:
                taints_in = query_result.node_in[node_id]
                taints_out = query_result.node_out.get(node_id, taints_in)
            else:
                taints_in = sink_result.node_in.get(node_id, set())
                taints_out = sink_result.node_out.get(node_id, taints_in)
            self.analysis.record_node_state(node_id, taints_in, taints_out, predecessor=predecessor)
            predecessor = node_id

    def _summarize_node(self, node_id: int) -> NodeIRSummary:
        if node_id in self._summary_cache:
            return self._summary_cache[node_id]

        node = self.icfg.nodes.get(node_id)
        summary = NodeIRSummary(node_id=node_id)
        if not node:
            self._summary_cache[node_id] = summary
            return summary

        for ir_text in getattr(node, "irs", []) or []:
            instruction = self._parse_ir(node, ir_text)
            if instruction is None:
                continue
            summary.instructions.append(instruction)
            summary.defined_vars.update(instruction.defs)
            summary.used_vars.update(instruction.uses)
            summary.returned_vars.update(instruction.returns)
            if instruction.kind in {"call", "assignment", "unpack"} and node.is_external_call():
                summary.call_result_vars.update(instruction.defs)

        self._summary_cache[node_id] = summary
        return summary

    def _parse_ir(self, node: Any, ir_text: str) -> Optional[IRInstruction]:
        text = (ir_text or "").strip()
        if not text:
            return None

        if text.startswith("RETURN "):
            returned = self._extract_symbols(text[len("RETURN ") :])
            return IRInstruction(kind="return", uses=set(returned), returns=set(returned))

        if " = HIGH_LEVEL_CALL" in text or " = LOW_LEVEL_CALL" in text or " = INTERNAL_CALL" in text:
            lhs = self._extract_lhs_symbol(text)
            uses = set()
            dest_match = re.search(r"dest:([^,]+)", text)
            if dest_match:
                uses.update(self._extract_symbols(dest_match.group(1)))
            arg_match = re.search(r"arguments:\[(.*?)\]", text)
            if arg_match:
                uses.update(self._extract_symbols(arg_match.group(1)))
            value_match = re.search(r"value:([^\s]+)", text)
            if value_match:
                uses.update(self._extract_symbols(value_match.group(1)))
            return IRInstruction(kind="call", defs={lhs} if lhs else set(), uses=uses)

        if "= UNPACK " in text:
            lhs = self._extract_lhs_symbol(text)
            rhs = text.split("UNPACK ", 1)[1]
            return IRInstruction(
                kind="unpack",
                defs={lhs} if lhs else set(),
                uses=set(self._extract_symbols(rhs)),
            )

        if " -> " in text:
            lhs = self._extract_lhs_symbol(text)
            rhs = text.split("->", 1)[1]
            defs = {lhs} if lhs else set()
            defs.update(node.writes)
            return IRInstruction(
                kind="index",
                defs=defs,
                uses=set(self._extract_symbols(rhs)),
            )

        if " = SOLIDITY_CALL " in text:
            lhs = self._extract_lhs_symbol(text)
            args_match = re.search(r"\((.*?)\)", text)
            uses = set()
            if args_match:
                parts = self._split_args(args_match.group(1))
                if parts:
                    uses.update(self._extract_symbols(parts[0]))
            return IRInstruction(kind="guard", defs={lhs} if lhs else set(), uses=uses)

        if " := " in text:
            lhs, rhs = text.split(" := ", 1)
            lhs_symbol = self._extract_lhs_symbol(lhs)
            defs = {lhs_symbol} if lhs_symbol else set()
            if lhs_symbol and lhs_symbol.startswith("REF_") and node.writes:
                defs.update(node.writes)
            return IRInstruction(
                kind="assignment",
                defs=defs,
                uses=set(self._extract_symbols(rhs)),
            )

        if " = " in text:
            lhs, rhs = text.split(" = ", 1)
            lhs_symbol = self._extract_lhs_symbol(lhs)
            defs = {lhs_symbol} if lhs_symbol else set()
            if lhs_symbol and lhs_symbol.startswith("REF_") and node.writes:
                defs.update(node.writes)
            return IRInstruction(
                kind="binary",
                defs=defs,
                uses=set(self._extract_symbols(rhs)),
            )

        return None

    def _extract_lhs_symbol(self, text: str) -> Optional[str]:
        symbols = self._extract_symbols(text)
        return symbols[0] if symbols else None

    def _extract_symbols(self, text: str) -> List[str]:
        raw_tokens = self._symbol_pattern.findall(text or "")
        symbols: List[str] = []
        for token in raw_tokens:
            normalized = self._normalize_symbol(token)
            if not normalized:
                continue
            if normalized.lower() in self._ignored_symbols:
                continue
            if normalized[0].isupper() and not self._is_temporary(normalized):
                continue
            symbols.append(normalized)
        return symbols

    def _normalize_symbol(self, token: str) -> str:
        normalized = token.strip()
        replacements = {
            "msg.sender": "msg_sender",
            "msg.value": "msg_value",
            "tx.origin": "tx_origin",
            "block.timestamp": "block_timestamp",
            "block.number": "block_number",
        }
        normalized = replacements.get(normalized, normalized)
        return normalized

    def _split_args(self, arg_text: str) -> List[str]:
        args: List[str] = []
        current: List[str] = []
        depth = 0
        for char in arg_text:
            if char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
                continue
            if char in "([":
                depth += 1
            elif char in ")]":
                depth = max(0, depth - 1)
            current.append(char)
        if current:
            args.append("".join(current).strip())
        return args

    def _is_temporary(self, symbol: str) -> bool:
        return symbol.startswith(("TMP_", "REF_", "TUPLE_"))

    def _merge_paths(self, *paths: Sequence[int]) -> List[int]:
        merged: List[int] = []
        for path in paths:
            for node_id in path:
                if not merged or merged[-1] != node_id:
                    merged.append(node_id)
        return merged
