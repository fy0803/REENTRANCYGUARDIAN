#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional, Tuple

from models import LockScope


class LockScopeAnalyzer:
    """Infer coarse-grained lock scopes from modifiers and naming patterns."""

    def __init__(self, icfg_builder: Any, contracts_info: Dict[str, Any]):
        self.icfg = icfg_builder
        self.contracts_info = contracts_info
        self.lock_scopes: Dict[str, LockScope] = {}
        self.known_lock_patterns = [
            "reentrancyguard",
            "nonreentrant",
            "_locked",
            "locked",
            "_guard",
            "_mutex",
        ]

    def detect_lock_variables(self) -> Dict[str, Any]:
        detected: Dict[str, Any] = {}
        for func_key, meta in self.icfg.function_meta.items():
            contract_name = meta["contract"]
            function_name = meta["name"]
            modifiers = [m.lower() for m in meta.get("modifiers", [])]
            matched = [m for m in modifiers if any(p in m for p in self.known_lock_patterns)]
            if not matched:
                continue
            detected.setdefault(contract_name, {})
            for modifier in matched:
                detected[contract_name][modifier] = {
                    "type": "modifier",
                    "function": function_name,
                    "nodes": list(self.icfg.get_function_nodes(func_key)),
                }
        return detected

    def analyze_lock_scopes(self) -> Dict[str, LockScope]:
        scopes: Dict[str, LockScope] = {}
        detected = self.detect_lock_variables()
        counter = 0

        for contract_name, locks in detected.items():
            for lock_name, lock_info in locks.items():
                scope_id = f"lock_{contract_name}_{lock_name}_{counter}"
                counter += 1
                scope = LockScope(
                    lock_id=scope_id,
                    contract_name=contract_name,
                    function_name=lock_info["function"],
                    covered_node_ids=set(lock_info["nodes"]),
                    lock_type=lock_info["type"],
                    lock_variable=lock_name,
                )
                scopes[scope_id] = scope
                for node_id in scope.covered_node_ids:
                    node = self.icfg.nodes.get(node_id)
                    if not node:
                        continue
                    node.in_lock_scope = True
                    node.lock_id = scope_id

        self.lock_scopes = scopes
        return scopes

    def is_node_protected(self, node_id: int, state_var: str) -> bool:
        for scope in self.lock_scopes.values():
            if scope.covers_node(node_id) and (not scope.protected_states or state_var in scope.protected_states):
                return True
        return False

    def is_path_protected(self, node_ids: List[int], state_var: str) -> bool:
        for scope in self.lock_scopes.values():
            if scope.covers_path(node_ids) and (not scope.protected_states or state_var in scope.protected_states):
                return True
        return False

    def get_protecting_lock(self, node_id: int) -> Optional[LockScope]:
        for scope in self.lock_scopes.values():
            if scope.covers_node(node_id):
                return scope
        return None

    def find_lock_acquire_release(self, function: Any) -> Optional[Tuple[int, int]]:
        func_key = getattr(function, "function_key", None) or str(function)
        node_ids = self.icfg.get_function_nodes(func_key)
        if not node_ids:
            return None
        scope = self.get_protecting_lock(node_ids[0])
        if scope is None:
            return None
        return min(scope.covered_node_ids), max(scope.covered_node_ids)
