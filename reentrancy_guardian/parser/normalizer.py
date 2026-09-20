#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional

from models import NodeInfo


class Normalizer:
    """Normalize extracted metadata into lightweight NodeInfo objects."""

    def __init__(self):
        self.node_map: Dict[int, NodeInfo] = {}
        self.state_var_aliases: Dict[str, str] = {}

    def normalize_nodes(self, contracts_data: Dict[str, Any]) -> Dict[int, NodeInfo]:
        node_map: Dict[int, NodeInfo] = {}
        next_id = 1

        for _, func_info in contracts_data.get("functions", {}).items():
            contract_name = func_info.get("contract", "Unknown")
            func_name = func_info.get("name", "Unknown")
            visibility = func_info.get("visibility")
            state_mutability = func_info.get("state_mutability")
            readonly = bool(func_info.get("is_view") or func_info.get("is_pure"))
            modifiers = list(func_info.get("modifiers", []))

            for node_data in func_info.get("nodes", []):
                call_type = None
                call_target_contract = None
                call_target_function = None

                external_calls = node_data.get("external_calls", [])
                internal_calls = node_data.get("internal_calls", [])
                if external_calls:
                    primary = external_calls[0]
                    call_type = self.normalize_call_type(primary)
                    call_target_contract = primary.get("target_contract")
                    call_target_function = primary.get("target_function")
                elif internal_calls:
                    primary = internal_calls[0]
                    call_type = self.normalize_call_type(primary)
                    call_target_contract = primary.get("target_contract")
                    call_target_function = primary.get("target_function")

                node_map[next_id] = NodeInfo(
                    node_id=next_id,
                    contract_name=contract_name,
                    function_name=func_name,
                    reads=set(self.normalize_state_variables(list(node_data.get("reads", set())))),
                    writes=set(self.normalize_state_variables(list(node_data.get("writes", set())))),
                    call_type=call_type,
                    call_target_contract=call_target_contract,
                    call_target_function=call_target_function,
                    node_type=node_data.get("type", ""),
                    source_node_id=node_data.get("slither_node_id"),
                    visibility=visibility,
                    state_mutability=state_mutability,
                    modifiers=modifiers,
                    expression=node_data.get("expression", "") or "",
                    irs=list(node_data.get("irs", [])),
                    ir_types=list(node_data.get("ir_types", [])),
                    readonly_context=readonly,
                    location={
                        "node_id": node_data.get("slither_node_id"),
                        "line": node_data.get("source_line", 0),
                        "file": node_data.get("source_file", ""),
                    },
                )
                next_id += 1

        self.node_map = node_map
        return node_map

    def normalize_state_variables(self, var_list: List[str]) -> List[str]:
        return [self.resolve_alias(var_name) for var_name in var_list if var_name]

    def normalize_call_type(self, call_info: Dict[str, Any]) -> Optional[str]:
        raw_type = str(call_info.get("type", "")).lower()
        if raw_type in {"highlevel", "high_level", "high_level_call"}:
            return "high_level_call"
        if raw_type in {"internal", "internal_call"}:
            return "internal_call"
        if raw_type in {"library", "library_call"}:
            return "library_call"
        if raw_type in {"delegatecall", "staticcall", "callcode", "call"}:
            return raw_type
        if raw_type in {"lowlevel", "low_level", "low_level_call"}:
            return "low_level_call"
        return raw_type or None

    def get_node_info(self, node_id: int) -> Optional[NodeInfo]:
        return self.node_map.get(node_id)

    def add_alias(self, original: str, alias: str) -> None:
        self.state_var_aliases[alias] = original

    def resolve_alias(self, var_name: str) -> str:
        return self.state_var_aliases.get(var_name, var_name)
