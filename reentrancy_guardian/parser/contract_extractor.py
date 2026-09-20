#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Set


class ContractExtractor:
    """Extract contract/function/node metadata from Slither objects."""

    def __init__(self, slither: Any):
        self.slither = slither
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.state_variables: Dict[str, Dict[str, Any]] = {}
        self.call_graph: Dict[str, List[str]] = {}

    def extract_all(self) -> Dict[str, Any]:
        self.extract_contracts()
        self.extract_state_variables()
        self.build_call_graph()
        return {
            "contracts": self.contracts,
            "functions": self.functions,
            "state_variables": self.state_variables,
            "call_graph": self.call_graph,
        }

    def extract_contracts(self) -> Dict[str, Any]:
        for contract in self.slither.contracts:
            self.contracts[contract.name] = {
                "name": contract.name,
                "functions": [f.name for f in contract.functions],
                "state_variables": [sv.name for sv in contract.state_variables],
                "parent_classes": [p.name for p in contract.inheritance if hasattr(p, "name")],
            }
            for func in contract.functions:
                self._extract_function_details(contract, func)
        return self.contracts

    def _extract_function_details(self, contract: Any, func: Any) -> None:
        func_key = f"{contract.name}.{func.name}"
        visibility = getattr(func, "visibility", None)
        state_mutability = getattr(func, "state_mutability", None)
        is_view = bool(getattr(func, "view", False) or state_mutability == "view")
        is_pure = bool(getattr(func, "pure", False) or state_mutability == "pure")
        modifiers = [m.name for m in getattr(func, "modifiers", []) if hasattr(m, "name")]

        self.functions[func_key] = {
            "contract": contract.name,
            "name": func.name,
            "visibility": visibility,
            "state_mutability": state_mutability,
            "is_constructor": bool(getattr(func, "is_constructor", False)),
            "is_view": is_view,
            "is_pure": is_pure,
            "modifiers": modifiers,
            "reads": {sv.name for sv in getattr(func, "state_variables_read", []) if sv},
            "writes": {sv.name for sv in getattr(func, "state_variables_written", []) if sv},
            "nodes": [],
        }

        for index, node in enumerate(func.nodes):
            node_info = {
                "node_id": index,
                "slither_node_id": getattr(node, "node_id", index),
                "type": str(getattr(node, "type", "")),
                "reads": {sv.name for sv in getattr(node, "state_variables_read", []) if sv},
                "writes": {sv.name for sv in getattr(node, "state_variables_written", []) if sv},
                "external_calls": self._extract_external_calls(node),
                "internal_calls": self._extract_internal_calls(node),
                "expression": str(getattr(node, "expression", "") or ""),
                "irs": [str(ir) for ir in getattr(node, "irs", []) or []],
                "ir_types": [type(ir).__name__ for ir in getattr(node, "irs", []) or []],
                "source_line": self._get_source_line(node),
                "source_file": self._get_source_file(node),
            }
            self.functions[func_key]["nodes"].append(node_info)

    def _extract_external_calls(self, node: Any) -> List[Dict[str, Any]]:
        calls: List[Dict[str, Any]] = []

        for raw in getattr(node, "high_level_calls", []) or []:
            if isinstance(raw, tuple) and len(raw) == 2:
                target_contract, operation = raw
                calls.append(
                    {
                        "type": "high_level_call",
                        "target_contract": getattr(target_contract, "name", None),
                        "target_function": str(getattr(operation, "function_name", None) or getattr(operation, "function", "")),
                    }
                )

        for raw in getattr(node, "library_calls", []) or []:
            if isinstance(raw, tuple) and len(raw) == 2:
                target_contract, operation = raw
                calls.append(
                    {
                        "type": "library_call",
                        "target_contract": getattr(target_contract, "name", None),
                        "target_function": str(getattr(operation, "function_name", None) or getattr(operation, "function", "")),
                    }
                )

        for raw in getattr(node, "low_level_calls", []) or []:
            call_type = str(getattr(raw, "function_name", "low_level_call"))
            calls.append(
                {
                    "type": call_type,
                    "target_contract": None,
                    "target_function": call_type,
                    "destination": str(getattr(raw, "destination", "")),
                }
            )

        return calls

    def _extract_internal_calls(self, node: Any) -> List[Dict[str, Any]]:
        calls: List[Dict[str, Any]] = []
        for raw in getattr(node, "internal_calls", []) or []:
            function = getattr(raw, "function", None)
            if function is None or not hasattr(function, "name"):
                continue
            target_contract = getattr(getattr(function, "contract_declarer", None), "name", None)
            if target_contract is None:
                contract = getattr(function, "contract", None)
                target_contract = getattr(contract, "name", None)
            calls.append(
                {
                    "type": "internal_call",
                    "target_contract": target_contract,
                    "target_function": function.name,
                }
            )
        return calls

    def extract_functions(self, contract_name: str) -> List[Dict[str, Any]]:
        return [info for info in self.functions.values() if info["contract"] == contract_name]

    def extract_state_variables(self, contract_name: str = None) -> Dict[str, Dict[str, Any]]:
        for contract in self.slither.contracts:
            if contract_name and contract.name != contract_name:
                continue
            for state_var in contract.state_variables:
                key = f"{contract.name}.{state_var.name}"
                self.state_variables[key] = {
                    "contract": contract.name,
                    "name": state_var.name,
                    "type": str(getattr(state_var, "type", "unknown")),
                    "visibility": getattr(state_var, "visibility", "internal"),
                    "is_immutable": bool(getattr(state_var, "is_immutable", False)),
                }
        return self.state_variables

    def build_call_graph(self) -> Dict[str, List[str]]:
        self.call_graph = {}
        for func_key, func_info in self.functions.items():
            callees: Set[str] = set()
            for node in func_info.get("nodes", []):
                for call in node.get("external_calls", []):
                    target_contract = call.get("target_contract")
                    target_function = call.get("target_function")
                    if target_contract and target_function:
                        callees.add(f"{target_contract}.{target_function}")
                for call in node.get("internal_calls", []):
                    target_contract = call.get("target_contract")
                    target_function = call.get("target_function")
                    if target_contract and target_function:
                        callees.add(f"{target_contract}.{target_function}")
            self.call_graph[func_key] = sorted(callees)
        return self.call_graph

    def extract_nodes(self, function: Any) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for node in function.nodes:
            result.append(
                {
                    "slither_node_id": getattr(node, "node_id", None),
                    "type": str(getattr(node, "type", "")),
                    "reads": {sv.name for sv in getattr(node, "state_variables_read", []) if sv},
                    "writes": {sv.name for sv in getattr(node, "state_variables_written", []) if sv},
                }
            )
        return result

    def extract_read_write_sets(self, function: Any) -> tuple[Set[str], Set[str]]:
        reads = {sv.name for sv in getattr(function, "state_variables_read", []) if sv}
        writes = {sv.name for sv in getattr(function, "state_variables_written", []) if sv}
        return reads, writes

    def _get_source_line(self, node: Any) -> int:
        try:
            source_mapping = getattr(node, "source_mapping", None)
            if source_mapping and getattr(source_mapping, "lines", None):
                return source_mapping.lines[0]
        except Exception:
            return 0
        return 0

    def _get_source_file(self, node: Any) -> str:
        try:
            source_mapping = getattr(node, "source_mapping", None)
            filename = getattr(source_mapping, "filename", None)
            absolute = getattr(filename, "absolute", None)
            if absolute:
                return str(absolute)
        except Exception:
            return ""
        return ""
