#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional

from .icfg_builder import ICFGBuilder


class IntraproceduralCFGBuilder(ICFGBuilder):
    """
    Build only per-function CFG nodes and control-flow edges.

    This is used for the no-ICFG ablation: it keeps Slither parsing and the
    normalized node facts, but removes call/return stitching and all semantic
    enhancement layers from the analysis graph.
    """

    def __init__(self, strip_delegatecall_storage_ownership: bool = False):
        super().__init__(enable_cross_contract_path_recovery=False)
        self.strip_delegatecall_storage_ownership = strip_delegatecall_storage_ownership

    def build_from_contracts(
        self,
        contracts: List[Any],
        normalized_nodes: Optional[Dict[int, Any]] = None,
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
        if self.strip_delegatecall_storage_ownership:
            self._strip_delegatecall_storage_ownership()
        self._clear_query_caches()

    def _strip_delegatecall_storage_ownership(self) -> None:
        for node in self.nodes.values():
            node.exec_owner = None
            node.storage_host = None
