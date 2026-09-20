#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Set, Tuple


class SemanticEdgeAnalyzer:
    """Add callback, read-only, and alias relations on top of the ICFG."""

    def __init__(self, icfg_builder: Any, contracts_info: Dict[str, Any]):
        self.icfg = icfg_builder
        self.contracts_info = contracts_info

        self.callback_edges: List[Tuple[int, int]] = []
        self.readonly_edges: List[Tuple[int, int]] = []
        self.alias_edges: List[Tuple[int, int]] = []

    def analyze_callback_edges(self) -> List[Tuple[int, int]]:
        edges: List[Tuple[int, int]] = []

        for node_id, node in self.icfg.nodes.items():
            if not node.is_reentrancy_sink():
                continue

            for entry_id in self._collect_cross_contract_callback_entries(node_id, node):
                self.icfg.add_semantic_edge(node_id, entry_id, "callback_cross_contract")
                edges.append((node_id, entry_id))

        self.callback_edges = edges
        return edges

    def _collect_cross_contract_callback_entries(self, node_id: int, node: Any) -> List[int]:
        entry_ids: List[int] = []
        for callee_entry in self.icfg.get_callsite_callee_entries(node_id):
            callee_node = self.icfg.nodes.get(callee_entry)
            if not callee_node:
                continue
            if callee_node.contract_name == node.contract_name:
                continue

            meta = self.icfg.function_meta.get(callee_node.function_key, {})
            if meta.get("visibility") not in {"public", "external"}:
                continue
            if meta.get("readonly"):
                continue
            if meta.get("is_constructor"):
                continue

            reads, writes = self.icfg.get_function_state_access(callee_node.function_key)
            if not (reads or writes):
                continue

            entry_ids.append(callee_entry)

        return sorted(set(entry_ids))

    def analyze_readonly_edges(self) -> List[Tuple[int, int]]:
        edges: List[Tuple[int, int]] = []
        query_functions = {
            func_key: meta
            for func_key, meta in self.icfg.function_meta.items()
            if meta.get("readonly")
        }

        query_reads: Dict[str, Set[str]] = {}
        for func_key in query_functions:
            reads, _ = self.icfg.get_function_state_access(func_key)
            query_reads[func_key] = reads

        for node_id, node in self.icfg.nodes.items():
            if not node.writes:
                continue
            for func_key, reads in query_reads.items():
                if not (node.writes & reads):
                    continue
                entry_id = self.icfg.get_function_entry(func_key)
                if entry_id is None:
                    continue
                self.icfg.add_semantic_edge(node_id, entry_id, "readonly_dep")
                edges.append((node_id, entry_id))

        for src, dst in self.icfg.edges_call:
            target_node = self.icfg.nodes.get(dst)
            caller_node = self.icfg.nodes.get(src)
            if not target_node or not caller_node:
                continue
            target_func = target_node.function_key
            if target_func not in query_functions:
                continue
            self.icfg.add_semantic_edge(dst, src, "readonly_sink")
            edges.append((dst, src))

        self.readonly_edges = edges
        return edges

    def analyze_alias_edges(self) -> List[Tuple[int, int]]:
        edges: List[Tuple[int, int]] = []

        delegate_nodes = [node for node in self.icfg.nodes.values() if node.is_delegatecall()]
        if not delegate_nodes:
            self.alias_edges = []
            return []

        state_writers = [node for node in self.icfg.nodes.values() if node.writes]

        for node in delegate_nodes:
            for target_key in node.call_targets:
                entry_id = self.icfg.get_function_entry(target_key)
                if entry_id is not None:
                    self.icfg.add_semantic_edge(node.node_id, entry_id, "delegatecall")
                    edges.append((node.node_id, entry_id))

                for callee_node_id in self.icfg.get_function_nodes(target_key):
                    callee_node = self.icfg.nodes.get(callee_node_id)
                    if not callee_node or not callee_node.has_state_access():
                        continue
                    self.icfg.add_semantic_edge(node.node_id, callee_node_id, "alias")
                    edges.append((node.node_id, callee_node_id))

            for writer in state_writers:
                if writer.contract_name != node.contract_name:
                    continue
                if writer.node_id == node.node_id:
                    continue
                self.icfg.add_semantic_edge(node.node_id, writer.node_id, "alias")
                edges.append((node.node_id, writer.node_id))

        self.alias_edges = edges
        return edges

    def identify_entry_functions(self, target_contract: str) -> List[str]:
        entries: List[str] = []
        for func_key in self.icfg.get_functions_by_contract(target_contract):
            meta = self.icfg.function_meta.get(func_key, {})
            if meta.get("visibility") not in {"public", "external"}:
                continue
            if meta.get("readonly"):
                continue
            reads, writes = self.icfg.get_function_state_access(func_key)
            if reads or writes:
                entries.append(func_key)
        return entries

    def identify_view_functions(self, target_contract: str) -> Dict[str, Set[str]]:
        result: Dict[str, Set[str]] = {}
        for func_key in self.icfg.get_functions_by_contract(target_contract):
            meta = self.icfg.function_meta.get(func_key, {})
            if not meta.get("readonly"):
                continue
            reads, _ = self.icfg.get_function_state_access(func_key)
            if reads:
                result[func_key] = reads
        return result
