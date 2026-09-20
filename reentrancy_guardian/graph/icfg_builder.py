#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from collections import deque, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from models import NodeInfo


class ICFGBuilder:
    """Build a semantic-friendly interprocedural CFG from Slither."""

    def __init__(
        self,
        enable_cross_contract_path_recovery: bool = True,
        enable_state_access_semantics: bool = True,
    ):
        self.nodes: Dict[int, NodeInfo] = {}
        self.edges_cf: List[Tuple[int, int]] = []
        self.edges_call: List[Tuple[int, int]] = []
        self.edges_ret: List[Tuple[int, int]] = []
        self.edges_sem: List[Tuple[int, int, str]] = []
        self.enable_cross_contract_path_recovery = enable_cross_contract_path_recovery
        self.enable_state_access_semantics = enable_state_access_semantics

        self.contracts: Set[str] = set()
        self.functions: Dict[str, List[int]] = {}
        self.function_entries: Dict[str, int] = {}
        self.function_exits: Dict[str, List[int]] = {}
        self.function_meta: Dict[str, Dict[str, Any]] = {}
        self.callsite_followups: Dict[int, Optional[int]] = {}
        self.callsite_callee_entries: Dict[int, List[int]] = {}
        self.callsite_callee_exits: Dict[int, List[int]] = {}

        self._function_objects: Dict[str, Any] = {}
        self._function_sequences: Dict[str, List[Dict[str, Any]]] = {}
        self._function_raw_to_global: Dict[str, Dict[int, int]] = {}
        self._function_inlines_modifiers: Set[str] = set()
        self._sequence_node_to_global: Dict[int, int] = {}
        self._raw_node_to_global: Dict[int, int] = {}
        self._next_node_id = 1
        self._low_level_target_cache: Dict[Tuple[Optional[str], str], List[str]] = {}
        self._contract_state_var_contracts: Dict[str, Dict[str, Set[str]]] = {}
        self._state_var_contract_aliases: Dict[str, Dict[str, Set[str]]] = {}
        self._constructor_sender_state_vars: Dict[str, Set[str]] = {}
        self._creator_contracts_by_created_contract: Dict[str, Set[str]] = {}
        self._execution_state_slice_cache: Dict[Tuple[str, int, Optional[int]], Set[Tuple[int, Tuple[int, ...]]]] = {}
        self._reachable_execution_state_cache: Dict[
            Tuple[Tuple[Tuple[int, Tuple[int, ...]], ...], int, Optional[int]],
            Set[Tuple[int, Tuple[int, ...]]],
        ] = {}
        self._execution_path_exists_cache: Dict[Tuple[int, int, int], bool] = {}
        self._execution_state_successors_cache: Dict[
            Tuple[int, Tuple[int, ...]],
            List[Tuple[int, Tuple[int, ...]]],
        ] = {}

    def add_node(self, node_info: NodeInfo) -> None:
        self.nodes[node_info.node_id] = node_info
        func_key = node_info.function_key
        self.functions.setdefault(func_key, []).append(node_info.node_id)
        self.contracts.add(node_info.contract_name)

    def add_control_flow_edge(self, source_id: int, target_id: int) -> None:
        edge = (source_id, target_id)
        if edge not in self.edges_cf:
            self.edges_cf.append(edge)

    def add_call_edge(self, source_id: int, target_id: int) -> None:
        edge = (source_id, target_id)
        if edge not in self.edges_call:
            self.edges_call.append(edge)

    def add_return_edge(self, source_id: int, target_id: int) -> None:
        edge = (source_id, target_id)
        if edge not in self.edges_ret:
            self.edges_ret.append(edge)

    def add_semantic_edge(self, source_id: int, target_id: int, edge_type: str) -> None:
        edge = (source_id, target_id, edge_type)
        if edge not in self.edges_sem:
            self.edges_sem.append(edge)

    def build_from_contracts(
        self,
        contracts: List[Any],
        normalized_nodes: Optional[Dict[int, NodeInfo]] = None,
    ) -> None:
        self.nodes.clear()
        self.edges_cf.clear()
        self.edges_call.clear()
        self.edges_ret.clear()
        self.edges_sem.clear()
        self.contracts.clear()
        self.functions.clear()
        self.function_entries.clear()
        self.function_exits.clear()
        self.function_meta.clear()
        self.callsite_followups.clear()
        self.callsite_callee_entries.clear()
        self.callsite_callee_exits.clear()
        self._function_objects.clear()
        self._function_sequences.clear()
        self._function_raw_to_global.clear()
        self._function_inlines_modifiers.clear()
        self._sequence_node_to_global.clear()
        self._raw_node_to_global.clear()
        self._next_node_id = 1
        self._low_level_target_cache.clear()
        self._contract_state_var_contracts.clear()
        self._state_var_contract_aliases.clear()
        self._constructor_sender_state_vars.clear()
        self._creator_contracts_by_created_contract.clear()
        self._clear_query_caches()

        self._collect_contract_metadata(contracts)

        for contract in contracts:
            self.contracts.add(contract.name)
            for func in contract.functions:
                self._register_function_metadata(contract, func)

        for contract in contracts:
            for func in contract.functions:
                self._register_function(contract, func)

        for func_key, func in self._function_objects.items():
            self._link_control_flow(func_key, func)

        self._apply_normalized_nodes(normalized_nodes or {})

        for func_key, func in self._function_objects.items():
            self._link_call_edges(func_key, func)
        self._clear_query_caches()

    def _clear_query_caches(self) -> None:
        self._execution_state_slice_cache.clear()
        self._reachable_execution_state_cache.clear()
        self._execution_path_exists_cache.clear()
        self._execution_state_successors_cache.clear()

    def _apply_normalized_nodes(self, normalized_nodes: Dict[int, NodeInfo]) -> None:
        if not normalized_nodes:
            return

        by_source: Dict[Tuple[str, Optional[int]], List[NodeInfo]] = defaultdict(list)
        by_location: Dict[Tuple[str, str, int], List[NodeInfo]] = defaultdict(list)

        for normalized in sorted(
            normalized_nodes.values(),
            key=lambda node: (
                node.function_key,
                -1 if node.source_node_id is None else int(node.source_node_id),
                node.location.get("line", 0),
            ),
        ):
            by_source[(normalized.function_key, normalized.source_node_id)].append(normalized)
            location = normalized.location or {}
            by_location[
                (
                    normalized.function_key,
                    str(location.get("file", "")),
                    int(location.get("line", 0) or 0),
                )
            ].append(normalized)

        for node_id in sorted(self.nodes):
            node = self.nodes[node_id]
            normalized = None

            source_key = (node.function_key, node.source_node_id)
            if by_source.get(source_key):
                normalized = by_source[source_key].pop(0)
            else:
                location = node.location or {}
                location_key = (
                    node.function_key,
                    str(location.get("file", "")),
                    int(location.get("line", 0) or 0),
                )
                if by_location.get(location_key):
                    normalized = by_location[location_key].pop(0)

            if normalized is not None:
                self._merge_normalized_node(node, normalized)

    def _merge_normalized_node(self, node: NodeInfo, normalized: NodeInfo) -> None:
        if self.enable_state_access_semantics:
            if normalized.reads or not node.reads:
                node.reads = set(normalized.reads)
            if normalized.writes or not node.writes:
                node.writes = set(normalized.writes)

        merged_targets = list(node.call_targets)
        for target in normalized.call_targets:
            if target not in merged_targets:
                merged_targets.append(target)
        node.call_type = normalized.call_type or node.call_type
        if normalized.call_target_contract and (normalized.call_targets or not node.call_target_contract):
            node.call_target_contract = normalized.call_target_contract
        if normalized.call_target_function and (normalized.call_targets or not node.call_target_function):
            node.call_target_function = normalized.call_target_function
        if merged_targets:
            node.call_targets = merged_targets

        node.node_type = normalized.node_type or node.node_type
        node.visibility = normalized.visibility or node.visibility
        node.state_mutability = normalized.state_mutability or node.state_mutability
        node.modifiers = list(normalized.modifiers or node.modifiers)
        node.readonly_context = normalized.readonly_context or node.readonly_context
        node.expression = normalized.expression or node.expression
        node.irs = list(normalized.irs or node.irs)
        node.ir_types = list(normalized.ir_types or node.ir_types)

        normalized_location = normalized.location or {}
        current_location = dict(node.location or {})
        for key, value in normalized_location.items():
            if value not in (None, "", 0):
                current_location[key] = value
        node.location = current_location

    def _register_function(self, contract: Any, func: Any) -> None:
        func_key = f"{contract.name}.{func.name}"
        self._register_function_metadata(contract, func)
        state_mutability = self.function_meta[func_key]["state_mutability"]
        modifiers = list(self.function_meta[func_key]["modifiers"])
        readonly = bool(self.function_meta[func_key]["readonly"])
        self.functions[func_key] = []
        self.function_exits[func_key] = []
        self._function_raw_to_global[func_key] = {}

        effective_steps = self._expand_execution_steps(func)
        self._function_sequences[func_key] = effective_steps
        if any(step.get("origin") == "modifier" for step in effective_steps):
            self._function_inlines_modifiers.add(func_key)

        for step in effective_steps:
            raw_node = step["raw_node"]
            global_id = self._next_node_id
            self._next_node_id += 1
            self._sequence_node_to_global[id(step)] = global_id
            if step.get("origin") != "modifier":
                self._raw_node_to_global[id(raw_node)] = global_id
                self._function_raw_to_global[func_key][id(raw_node)] = global_id

            call_type, target_contract, target_function, call_targets = self._detect_call_info(
                contract.name,
                raw_node,
            )
            node_info = NodeInfo(
                node_id=global_id,
                contract_name=contract.name,
                function_name=func.name,
                reads=(
                    {sv.name for sv in getattr(raw_node, "state_variables_read", []) if sv}
                    if self.enable_state_access_semantics
                    else set()
                ),
                writes=(
                    {sv.name for sv in getattr(raw_node, "state_variables_written", []) if sv}
                    if self.enable_state_access_semantics
                    else set()
                ),
                call_type=call_type,
                call_target_contract=target_contract,
                call_target_function=target_function,
                call_targets=call_targets,
                node_type=str(getattr(raw_node, "type", "")),
                source_node_id=(
                    None if step.get("origin") == "modifier" else getattr(raw_node, "node_id", None)
                ),
                visibility=getattr(func, "visibility", None),
                state_mutability=state_mutability,
                modifiers=modifiers,
                expression=str(getattr(raw_node, "expression", "") or ""),
                irs=[str(ir) for ir in getattr(raw_node, "irs", []) or []],
                ir_types=[type(ir).__name__ for ir in getattr(raw_node, "irs", []) or []],
                readonly_context=readonly,
                exec_owner="caller" if call_type == "delegatecall" else "contract",
                storage_host=contract.name if call_type == "delegatecall" else None,
                location={
                    "node_id": getattr(raw_node, "node_id", None),
                    "line": self._get_source_line(raw_node),
                    "file": self._get_source_file(raw_node),
                },
            )
            self.add_node(node_info)

        if self.functions[func_key]:
            self.function_entries[func_key] = self.functions[func_key][0]
            self.function_exits[func_key] = self._infer_function_exits(func_key, func)

    def _register_function_metadata(self, contract: Any, func: Any) -> None:
        func_key = f"{contract.name}.{func.name}"
        modifiers = [m.name for m in getattr(func, "modifiers", []) if hasattr(m, "name")]
        state_mutability = getattr(func, "state_mutability", None)
        readonly = bool(
            getattr(func, "view", False)
            or getattr(func, "pure", False)
            or state_mutability in {"view", "pure"}
        )

        self.function_meta[func_key] = {
            "contract": contract.name,
            "name": func.name,
            "visibility": getattr(func, "visibility", None),
            "state_mutability": state_mutability,
            "readonly": readonly,
            "is_constructor": bool(getattr(func, "is_constructor", False)),
            "modifiers": modifiers,
            "function": func,
        }
        self._function_objects[func_key] = func
        self.functions.setdefault(func_key, [])
        self.function_exits.setdefault(func_key, [])
        self._function_raw_to_global.setdefault(func_key, {})

    def _link_control_flow(self, func_key: str, func: Any) -> None:
        if func_key in self._function_inlines_modifiers:
            node_ids = self.functions.get(func_key, [])
            for source_id, target_id in zip(node_ids, node_ids[1:]):
                self.add_control_flow_edge(source_id, target_id)
            return

        for raw_node in list(func.nodes):
            source_id = self._function_raw_to_global.get(func_key, {}).get(id(raw_node))
            if source_id is None:
                continue
            for son in getattr(raw_node, "sons", []) or []:
                target_id = self._function_raw_to_global.get(func_key, {}).get(id(son))
                if target_id is not None:
                    self.add_control_flow_edge(source_id, target_id)

    def _link_call_edges(self, func_key: str, func: Any) -> None:
        node_ids = self.functions.get(func_key, [])
        ordered_steps = self._function_sequences.get(
            func_key,
            [{"raw_node": raw_node, "origin": "function"} for raw_node in list(func.nodes)],
        )
        for index, step in enumerate(ordered_steps):
            raw_node = step["raw_node"]
            source_id = self._sequence_node_to_global.get(id(step))
            if source_id is None:
                continue

            source_node = self.nodes.get(source_id)
            target_keys = list(source_node.call_targets if source_node else self._resolve_call_targets(raw_node))
            return_target = self._find_return_target(node_ids, index, source_id)
            callee_entries: List[int] = []
            callee_exits: List[int] = []

            for target_key in target_keys:
                entry_id = self.function_entries.get(target_key)
                if entry_id is None:
                    continue
                target_contract = target_key.split(".", 1)[0]
                is_cross_contract = bool(
                    source_node
                    and target_contract
                    and target_contract != source_node.contract_name
                )
                if is_cross_contract and not self.enable_cross_contract_path_recovery:
                    continue
                self.add_call_edge(source_id, entry_id)
                callee_entries.append(entry_id)

                if return_target is not None:
                    for exit_id in self.get_function_exits(target_key):
                        self.add_return_edge(exit_id, return_target)
                        callee_exits.append(exit_id)

            if source_node and self._is_inter_contract_callsite(source_node):
                self.callsite_followups[source_id] = return_target
                self.callsite_callee_entries[source_id] = sorted(set(callee_entries))
                self.callsite_callee_exits[source_id] = sorted(set(callee_exits))

    def _resolve_call_targets(self, raw_node: Any) -> List[str]:
        targets: List[str] = []

        for raw in getattr(raw_node, "high_level_calls", []) or []:
            if isinstance(raw, tuple) and len(raw) == 2:
                target_contract, operation = raw
                contract_name = getattr(target_contract, "name", None)
                function_name = getattr(operation, "function_name", None) or str(
                    getattr(operation, "function", "")
                )
                if contract_name and function_name:
                    targets.append(f"{contract_name}.{function_name}")

        for raw in getattr(raw_node, "internal_calls", []) or []:
            function = getattr(raw, "function", None)
            if function is None or not hasattr(function, "name"):
                continue
            contract = getattr(function, "contract_declarer", None) or getattr(
                function, "contract", None
            )
            contract_name = getattr(contract, "name", None)
            if contract_name:
                targets.append(f"{contract_name}.{function.name}")

        for raw in getattr(raw_node, "library_calls", []) or []:
            if isinstance(raw, tuple) and len(raw) == 2:
                target_contract, operation = raw
                contract_name = getattr(target_contract, "name", None)
                function_name = getattr(operation, "function_name", None) or str(
                    getattr(operation, "function", "")
                )
                if contract_name and function_name:
                    targets.append(f"{contract_name}.{function_name}")

        for raw in getattr(raw_node, "low_level_calls", []) or []:
            call_type = str(getattr(raw, "function_name", "low_level_call")).lower()
            signature_name = self._extract_signature_name(raw_node, raw)
            targets.extend(self._resolve_low_level_call_targets(signature_name, call_type))

        return sorted(set(targets))

    def _find_return_target(
        self,
        node_ids: List[int],
        call_index: int,
        source_id: Optional[int] = None,
    ) -> Optional[int]:
        if source_id is not None:
            cfg_successors = sorted(dst for src, dst in self.edges_cf if src == source_id)
            if cfg_successors:
                return cfg_successors[0]
        if call_index + 1 < len(node_ids):
            return node_ids[call_index + 1]
        return None

    def _expand_execution_steps(self, func: Any) -> List[Dict[str, Any]]:
        initial_sequence = [
            {"raw_node": raw_node, "origin": "function"}
            for raw_node in self._order_nodes_by_control_flow(list(func.nodes))
        ]
        return self._expand_sequence(initial_sequence)

    def _expand_sequence(
        self,
        sequence: List[Dict[str, Any]],
        continuation: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        continuation = list(continuation or [])
        if not sequence:
            return self._expand_sequence(continuation, []) if continuation else []

        current = sequence[0]
        raw_node = current["raw_node"]
        rest = sequence[1:]
        node_type = str(getattr(raw_node, "type", "") or "")

        if current.get("origin") == "modifier" and "ENTRYPOINT" in node_type:
            return self._expand_sequence(rest, continuation)

        if "PLACEHOLDER" in node_type:
            return self._expand_sequence(list(continuation) + rest, [])

        modifier = self._resolve_modifier_call(raw_node)
        if modifier is not None:
            modifier_sequence = [
                {"raw_node": node, "origin": "modifier"}
                for node in self._order_nodes_by_control_flow(list(modifier.nodes))
            ]
            return self._expand_sequence(modifier_sequence, rest + continuation)

        return [current] + self._expand_sequence(rest, continuation)

    def _order_nodes_by_control_flow(self, nodes: List[Any]) -> List[Any]:
        if len(nodes) <= 1:
            return list(nodes)

        node_set = {id(node) for node in nodes}
        ordered: List[Any] = []
        visited: Set[int] = set()

        def visit(raw_node: Any) -> None:
            node_id = id(raw_node)
            if node_id in visited:
                return
            visited.add(node_id)
            ordered.append(raw_node)
            sons = [
                son for son in (getattr(raw_node, "sons", []) or []) if id(son) in node_set
            ]
            sons.sort(key=lambda node: getattr(node, "node_id", -1))
            for son in sons:
                visit(son)

        entries = [
            node
            for node in nodes
            if not (getattr(node, "fathers", []) or [])
            or "ENTRYPOINT" in str(getattr(node, "type", "") or "")
        ]
        entries.sort(key=lambda node: getattr(node, "node_id", -1))
        for entry in entries:
            visit(entry)

        for node in sorted(nodes, key=lambda current: getattr(current, "node_id", -1)):
            visit(node)

        return ordered

    def _resolve_modifier_call(self, raw_node: Any) -> Optional[Any]:
        for operation in getattr(raw_node, "internal_calls", []) or []:
            function = getattr(operation, "function", None)
            if function is None:
                continue
            if function.__class__.__name__ == "Modifier":
                return function
        return None

    def _is_inter_contract_callsite(self, node: NodeInfo) -> bool:
        return node.call_type in {
            "high_level_call",
            "library_call",
            "call",
            "delegatecall",
            "staticcall",
            "callcode",
            "low_level_call",
        }

    def _infer_function_exits(self, func_key: str, func: Any) -> List[int]:
        if func_key in self._function_inlines_modifiers:
            exit_ids: List[int] = []
            for node_id in self.functions.get(func_key, []):
                node = self.nodes.get(node_id)
                if not node:
                    continue
                node_type = str(node.node_type or "")
                if "RETURN" in node_type or "THROW" in node_type or "REVERT" in node_type:
                    exit_ids.append(node_id)
            if exit_ids:
                return sorted(set(exit_ids))
            node_ids = self.functions.get(func_key, [])
            return [node_ids[-1]] if node_ids else []

        exit_ids: List[int] = []
        for raw_node in list(func.nodes):
            global_id = self._raw_node_to_global.get(id(raw_node))
            if global_id is None:
                continue
            node_type = str(getattr(raw_node, "type", "") or "")
            sons = getattr(raw_node, "sons", []) or []
            if "RETURN" in node_type or "THROW" in node_type or "REVERT" in node_type or not sons:
                exit_ids.append(global_id)

        if exit_ids:
            return sorted(set(exit_ids))

        node_ids = self.functions.get(func_key, [])
        return [node_ids[-1]] if node_ids else []

    def _detect_call_info(
        self, contract_name: str, raw_node: Any
    ) -> Tuple[Optional[str], Optional[str], Optional[str], List[str]]:
        if getattr(raw_node, "high_level_calls", None):
            target_contract, operation = raw_node.high_level_calls[0]
            target_function = str(
                getattr(operation, "function_name", None) or getattr(operation, "function", "")
            )
            target_key = f"{getattr(target_contract, 'name', None)}.{target_function}"
            return (
                "high_level_call",
                getattr(target_contract, "name", None),
                target_function,
                [target_key] if getattr(target_contract, "name", None) and target_function else [],
            )

        if getattr(raw_node, "low_level_calls", None):
            operation = raw_node.low_level_calls[0]
            call_type = str(getattr(operation, "function_name", "low_level_call")).lower()
            signature_name = self._extract_signature_name(raw_node, operation)
            destination_contracts = self._infer_low_level_destination_contracts(contract_name, operation)
            empty_payload = self._uses_empty_low_level_payload(raw_node, operation)
            targets = self._resolve_low_level_call_targets(
                signature_name,
                call_type,
                destination_contracts=destination_contracts,
                empty_payload=empty_payload,
            )
            target_contract = targets[0].split(".", 1)[0] if targets else None
            target_function = signature_name or (targets[0].split(".", 1)[1] if targets else call_type)
            return call_type, target_contract, target_function, targets

        if getattr(raw_node, "internal_calls", None):
            targets: List[str] = []
            first_contract: Optional[str] = None
            first_function: Optional[str] = None
            for operation in getattr(raw_node, "internal_calls", []) or []:
                function = getattr(operation, "function", None)
                if function is None or not hasattr(function, "name"):
                    continue
                contract = getattr(function, "contract_declarer", None) or getattr(
                    function, "contract", None
                )
                contract_name = getattr(contract, "name", None)
                if not contract_name:
                    continue
                function_name = function.name
                targets.append(f"{contract_name}.{function_name}")
                if first_contract is None:
                    first_contract = contract_name
                    first_function = function_name
            if targets:
                return (
                    "internal_call",
                    first_contract,
                    first_function,
                    sorted(set(targets)),
                )
            return "internal_call", None, None, []

        if getattr(raw_node, "library_calls", None):
            target_contract, operation = raw_node.library_calls[0]
            target_function = str(
                getattr(operation, "function_name", None) or getattr(operation, "function", "")
            )
            target_key = f"{getattr(target_contract, 'name', None)}.{target_function}"
            return (
                "library_call",
                getattr(target_contract, "name", None),
                target_function,
                [target_key] if getattr(target_contract, "name", None) and target_function else [],
            )

        return None, None, None, []

    def _resolve_low_level_call_targets(
        self,
        signature_name: Optional[str],
        call_type: str,
        destination_contracts: Optional[Set[str]] = None,
        empty_payload: bool = False,
    ) -> List[str]:
        cache_key = (signature_name, call_type)
        if cache_key in self._low_level_target_cache and not destination_contracts and not empty_payload:
            return list(self._low_level_target_cache[cache_key])

        destination_contracts = set(destination_contracts or set())

        candidates: List[str] = []
        if signature_name:
            for func_key, meta in self.function_meta.items():
                if meta.get("name") != signature_name:
                    continue
                if meta.get("is_constructor"):
                    continue
                visibility = meta.get("visibility")
                if visibility in {"private", "internal"}:
                    continue
                if destination_contracts and meta.get("contract") not in destination_contracts:
                    continue
                if call_type == "staticcall" and not meta.get("readonly"):
                    continue
                candidates.append(func_key)
        elif destination_contracts:
            for contract_name in sorted(destination_contracts):
                contract_functions = self.get_functions_by_contract(contract_name)
                fallback_like: List[str] = []
                for func_key in contract_functions:
                    meta = self.function_meta.get(func_key, {})
                    if meta.get("is_constructor"):
                        continue
                    if meta.get("visibility") not in {"public", "external"}:
                        continue
                    if call_type == "staticcall":
                        if meta.get("readonly"):
                            candidates.append(func_key)
                        continue
                    if meta.get("name") in {"fallback", "receive"}:
                        fallback_like.append(func_key)
                if fallback_like:
                    candidates.extend(fallback_like)
                elif not empty_payload:
                    for func_key in contract_functions:
                        meta = self.function_meta.get(func_key, {})
                        if meta.get("is_constructor"):
                            continue
                        if meta.get("visibility") not in {"public", "external"}:
                            continue
                        if not meta.get("readonly"):
                            candidates.append(func_key)

        result = sorted(set(candidates))
        if not destination_contracts and not empty_payload:
            self._low_level_target_cache[cache_key] = result
        return result

    def _extract_signature_name(self, raw_node: Any, operation: Any = None) -> Optional[str]:
        expression = str(getattr(raw_node, "expression", "") or "")
        patterns = [
            r"encodeWithSignature\((?:\"|')?([A-Za-z_][A-Za-z0-9_]*)\(",
            r"encodeWithSelector\((?:\"|')?([A-Za-z_][A-Za-z0-9_]*)\(",
            r"\.([A-Za-z_][A-Za-z0-9_]*)\(",
        ]
        banned_names = {"call", "delegatecall", "staticcall", "callcode", "low_level_call", "value", "gas"}
        for index, pattern in enumerate(patterns):
            if index < 2:
                match = re.search(pattern, expression)
                if match:
                    return match.group(1)
                continue
            for match in re.finditer(pattern, expression):
                candidate = match.group(1)
                if candidate not in banned_names:
                    return candidate

        function_name = getattr(operation, "function_name", None)
        if function_name:
            function_name = str(function_name).lower()
            if function_name not in {"call", "delegatecall", "staticcall", "callcode", "low_level_call"}:
                return function_name
        return None

    def _collect_contract_metadata(self, contracts: List[Any]) -> None:
        self._contract_state_var_contracts = {}
        self._state_var_contract_aliases = {}
        self._constructor_sender_state_vars = {}
        self._creator_contracts_by_created_contract = {}

        for contract in contracts:
            state_var_contracts: Dict[str, Set[str]] = {}
            for state_var in getattr(contract, "state_variables", []) or []:
                contract_targets = self._extract_state_var_contract_targets(state_var)
                if contract_targets:
                    state_var_contracts[state_var.name] = contract_targets
            self._contract_state_var_contracts[contract.name] = state_var_contracts
            self._state_var_contract_aliases[contract.name] = {}
            self._constructor_sender_state_vars[contract.name] = set()

        for contract in contracts:
            for func in getattr(contract, "functions", []) or []:
                constructor_context = bool(getattr(func, "is_constructor", False) or func.name == "slitherConstructorVariables")
                for raw_node in getattr(func, "nodes", []) or []:
                    for ir in getattr(raw_node, "irs", []) or []:
                        if type(ir).__name__ == "NewContract":
                            created_contract = self._normalize_contract_name(
                                getattr(ir, "contract_name", None) or getattr(ir, "contract_created", None)
                            )
                            if created_contract:
                                self._creator_contracts_by_created_contract.setdefault(created_contract, set()).add(contract.name)
                            continue

                        if type(ir).__name__ != "Assignment":
                            continue
                        lvalue = getattr(ir, "lvalue", None)
                        rvalue = getattr(ir, "rvalue", None)
                        if type(lvalue).__name__ != "StateVariable":
                            continue

                        left_name = getattr(lvalue, "name", str(lvalue))
                        if constructor_context and str(rvalue) == "msg.sender":
                            self._constructor_sender_state_vars.setdefault(contract.name, set()).add(left_name)
                            continue

                        if type(rvalue).__name__ == "StateVariable":
                            right_name = getattr(rvalue, "name", str(rvalue))
                            target_contracts = set(self._state_variable_contract_targets(contract.name, right_name))
                            if target_contracts:
                                aliases = self._state_var_contract_aliases.setdefault(contract.name, {})
                                aliases.setdefault(left_name, set()).update(target_contracts)

    def _extract_state_var_contract_targets(self, state_var: Any) -> Set[str]:
        state_type = getattr(state_var, "type", None)
        if state_type is None:
            return set()

        if type(state_type).__name__ == "UserDefinedType":
            target = self._normalize_contract_name(getattr(state_type, "type", None))
            return {target} if target else set()
        return set()

    def _normalize_contract_name(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        name = getattr(value, "name", None)
        if name:
            return str(name)
        text = str(value).strip()
        return text or None

    def _state_variable_contract_targets(self, contract_name: str, variable_name: str) -> Set[str]:
        direct = self._contract_state_var_contracts.get(contract_name, {}).get(variable_name, set())
        if direct:
            return set(direct)

        aliases = self._state_var_contract_aliases.get(contract_name, {}).get(variable_name, set())
        if aliases:
            return set(aliases)

        if variable_name in self._constructor_sender_state_vars.get(contract_name, set()):
            return set(self._creator_contracts_by_created_contract.get(contract_name, set()))

        return set()

    def _infer_low_level_destination_contracts(self, contract_name: str, operation: Any) -> Set[str]:
        destination = str(getattr(operation, "destination", "") or "").strip()
        if not destination:
            return set()

        unwrapped = destination
        wrappers = [
            r"^address\((?P<inner>[^()]+)\)$",
            r"^address payable\((?P<inner>[^()]+)\)$",
            r"^payable\((?P<inner>[^()]+)\)$",
        ]
        changed = True
        while changed:
            changed = False
            for pattern in wrappers:
                match = re.match(pattern, unwrapped)
                if match:
                    unwrapped = match.group("inner").strip()
                    changed = True
                    break

        if unwrapped in {"this", "address(this)"}:
            return {contract_name}
        if unwrapped in {"msg.sender", "tx.origin"}:
            return set()

        return self._state_variable_contract_targets(contract_name, unwrapped)

    def _uses_empty_low_level_payload(self, raw_node: Any, operation: Any) -> bool:
        expression = str(getattr(raw_node, "expression", "") or "")
        if "(\"\")" in expression or "new bytes(0)" in expression:
            return True

        arguments = getattr(operation, "arguments", None)
        return arguments is not None and len(arguments) == 0

    def _get_source_line(self, raw_node: Any) -> int:
        try:
            source_mapping = getattr(raw_node, "source_mapping", None)
            if source_mapping and getattr(source_mapping, "lines", None):
                return source_mapping.lines[0]
        except Exception:
            return 0
        return 0

    def _get_source_file(self, raw_node: Any) -> str:
        try:
            source_mapping = getattr(raw_node, "source_mapping", None)
            filename = getattr(source_mapping, "filename", None)
            absolute = getattr(filename, "absolute", None)
            if absolute:
                return str(absolute)
        except Exception:
            return ""
        return ""

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_nodes": len(self.nodes),
            "total_contracts": len(self.contracts),
            "total_functions": len(self.functions),
            "control_flow_edges": len(self.edges_cf),
            "call_edges": len(self.edges_call),
            "return_edges": len(self.edges_ret),
            "semantic_edges": len(self.edges_sem),
        }

    def get_callsite_statistics(self) -> Dict[str, Any]:
        return {
            "callsite_blocks": len(self.callsite_followups),
            "callsites_with_followup": sum(
                1 for target in self.callsite_followups.values() if target is not None
            ),
            "inter_contract_entries": sum(len(entries) for entries in self.callsite_callee_entries.values()),
            "inter_contract_exits": sum(len(exits) for exits in self.callsite_callee_exits.values()),
        }

    def get_function_nodes(self, func_key: str) -> List[int]:
        return list(self.functions.get(func_key, []))

    def get_function_entry(self, func_key: str) -> Optional[int]:
        return self.function_entries.get(func_key)

    def get_function_exits(self, func_key: str) -> List[int]:
        return list(self.function_exits.get(func_key, []))

    def get_inter_contract_callsites(self) -> List[int]:
        return sorted(self.callsite_followups)

    def get_callsite_followup(self, node_id: int) -> Optional[int]:
        return self.callsite_followups.get(node_id)

    def get_callsite_callee_entries(self, node_id: int) -> List[int]:
        return list(self.callsite_callee_entries.get(node_id, []))

    def get_callsite_callee_exits(self, node_id: int) -> List[int]:
        return list(self.callsite_callee_exits.get(node_id, []))

    def get_functions_by_contract(self, contract_name: str) -> List[str]:
        return [
            func_key
            for func_key, meta in self.function_meta.items()
            if meta.get("contract") == contract_name
        ]

    def get_function_state_access(self, func_key: str) -> Tuple[Set[str], Set[str]]:
        reads: Set[str] = set()
        writes: Set[str] = set()
        for node_id in self.functions.get(func_key, []):
            node = self.nodes.get(node_id)
            if not node:
                continue
            reads.update(node.reads)
            writes.update(node.writes)
        return reads, writes

    def get_successors(self, node_id: int, include_semantic: bool = True) -> Set[int]:
        successors = {dst for src, dst in self.edges_cf + self.edges_call + self.edges_ret if src == node_id}
        if include_semantic:
            successors.update(dst for src, dst, _ in self.edges_sem if src == node_id)
        return successors

    def get_execution_successors(self, node_id: int) -> Set[int]:
        successors = {dst for src, dst in self.edges_cf + self.edges_ret if src == node_id}
        node = self.nodes.get(node_id)
        if node and node.call_type in {"internal_call", "library_call"}:
            successors.update(dst for src, dst in self.edges_call if src == node_id)
        return successors

    def get_predecessors(self, node_id: int, include_semantic: bool = True) -> Set[int]:
        predecessors = {src for src, dst in self.edges_cf + self.edges_call + self.edges_ret if dst == node_id}
        if include_semantic:
            predecessors.update(src for src, dst, _ in self.edges_sem if dst == node_id)
        return predecessors

    def get_semantic_successors(self, node_id: int, edge_type: Optional[str] = None) -> Set[int]:
        return {
            dst
            for src, dst, current_type in self.edges_sem
            if src == node_id and (edge_type is None or current_type == edge_type)
        }

    def find_path(
        self,
        start_node: int,
        end_node: Optional[int],
        include_semantic: bool = True,
        semantic_types: Optional[Set[str]] = None,
        max_depth: int = 64,
    ) -> List[int]:
        if end_node is None:
            return [start_node] if start_node in self.nodes else []
        if start_node not in self.nodes or end_node not in self.nodes:
            return []
        if start_node == end_node:
            return [start_node]

        queue = deque([(start_node, [start_node])])
        visited = {start_node}

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            successors = set()
            successors.update(dst for src, dst in self.edges_cf if src == current)
            successors.update(dst for src, dst in self.edges_call if src == current)
            successors.update(dst for src, dst in self.edges_ret if src == current)
            if include_semantic:
                successors.update(
                    dst
                    for src, dst, edge_type in self.edges_sem
                    if src == current and (semantic_types is None or edge_type in semantic_types)
                )

            for successor in sorted(successors):
                if successor == end_node:
                    return path + [successor]
                if successor in visited:
                    continue
                visited.add(successor)
                queue.append((successor, path + [successor]))

        return []

    def find_execution_path(
        self,
        start_node: int,
        end_node: Optional[int],
        max_depth: int = 128,
    ) -> List[int]:
        if end_node is None:
            return [start_node] if start_node in self.nodes else []
        if start_node not in self.nodes or end_node not in self.nodes:
            return []
        if start_node == end_node:
            return [start_node]

        queue = deque([((start_node, ()), [start_node])])
        visited = {(start_node, ())}

        while queue:
            (current, stack), path = queue.popleft()
            if len(path) > max_depth:
                continue

            for successor, next_stack in self._get_execution_state_successors(current, stack):
                if successor == end_node:
                    return path + [successor]
                state = (successor, next_stack)
                if state in visited:
                    continue
                visited.add(state)
                queue.append((state, path + [successor]))

        return []

    def get_execution_slice(
        self,
        func_key: str,
        max_depth: int = 256,
        max_states: Optional[int] = None,
    ) -> Set[int]:
        return {
            node_id
            for node_id, _ in self.get_execution_state_slice(
                func_key,
                max_depth=max_depth,
                max_states=max_states,
            )
        }

    def get_execution_state_slice(
        self,
        func_key: str,
        max_depth: int = 256,
        max_states: Optional[int] = None,
    ) -> Set[Tuple[int, Tuple[int, ...]]]:
        cache_key = (func_key, max_depth, max_states)
        if cache_key in self._execution_state_slice_cache:
            return set(self._execution_state_slice_cache[cache_key])

        entry = self.get_function_entry(func_key)
        if entry is None:
            return set()

        start_state = (entry, ())
        result = self.get_reachable_execution_states(
            {start_state},
            max_depth=max_depth,
            max_states=max_states,
        )
        self._execution_state_slice_cache[cache_key] = set(result)
        return set(result)

    def get_reachable_execution_states(
        self,
        start_states: Set[Tuple[int, Tuple[int, ...]]],
        max_depth: int = 256,
        max_states: Optional[int] = None,
    ) -> Set[Tuple[int, Tuple[int, ...]]]:
        cache_key = (tuple(sorted(start_states)), max_depth, max_states)
        if cache_key in self._reachable_execution_state_cache:
            return set(self._reachable_execution_state_cache[cache_key])

        reachable: Set[Tuple[int, Tuple[int, ...]]] = set()
        queue = deque([(state, 0) for state in start_states])
        while queue:
            state, depth = queue.popleft()
            current, stack = state
            if state in reachable or depth > max_depth:
                continue
            reachable.add(state)
            if max_states is not None and len(reachable) >= max_states:
                break
            for successor, next_stack in self._get_execution_state_successors(current, stack):
                queue.append(((successor, next_stack), depth + 1))
        self._reachable_execution_state_cache[cache_key] = set(reachable)
        return reachable

    def execution_path_exists(
        self,
        start_node: int,
        end_node: int,
        max_depth: int = 128,
    ) -> bool:
        cache_key = (start_node, end_node, max_depth)
        if cache_key not in self._execution_path_exists_cache:
            self._execution_path_exists_cache[cache_key] = bool(
                self.find_execution_path(start_node, end_node, max_depth=max_depth)
            )
        return self._execution_path_exists_cache[cache_key]

    def _get_execution_state_successors(
        self,
        node_id: int,
        stack: Tuple[int, ...],
    ) -> List[Tuple[int, Tuple[int, ...]]]:
        cache_key = (node_id, stack)
        if cache_key in self._execution_state_successors_cache:
            return list(self._execution_state_successors_cache[cache_key])

        successors: List[Tuple[int, Tuple[int, ...]]] = []

        for dst in sorted(dst for src, dst in self.edges_cf if src == node_id):
            successors.append((dst, stack))

        node = self.nodes.get(node_id)
        if node and node.call_type in {"internal_call", "library_call"}:
            for callee_entry in sorted(dst for src, dst in self.edges_call if src == node_id):
                callee_node = self.nodes.get(callee_entry)
                callee_key = callee_node.function_key if callee_node else None
                return_targets = set()
                if callee_key:
                    callee_exits = set(self.get_function_exits(callee_key))
                    return_targets = {
                        dst for src, dst in self.edges_ret if src in callee_exits
                    }
                if return_targets:
                    for return_target in sorted(return_targets):
                        successors.append((callee_entry, stack + (return_target,)))
                else:
                    successors.append((callee_entry, stack))

        if stack:
            expected_return = stack[-1]
            if (node_id, expected_return) in self.edges_ret:
                successors.append((expected_return, stack[:-1]))

        self._execution_state_successors_cache[cache_key] = list(successors)
        return successors

    def path_exists(
        self,
        start_node: int,
        end_node: int,
        include_semantic: bool = True,
        semantic_types: Optional[Set[str]] = None,
        max_depth: int = 64,
    ) -> bool:
        return bool(
            self.find_path(
                start_node,
                end_node,
                include_semantic=include_semantic,
                semantic_types=semantic_types,
                max_depth=max_depth,
            )
        )
