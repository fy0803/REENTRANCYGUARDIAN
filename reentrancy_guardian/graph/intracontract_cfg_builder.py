#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, List

from .icfg_builder import ICFGBuilder


class IntraContractCFGBuilder(ICFGBuilder):
    """
    Build an ICFG with function-local and same-contract call/return edges only.

    This ablation keeps normalized node facts and intra-contract interprocedural
    structure, but removes cross-contract call/return stitching and the
    cross-contract callsite metadata used by callback recovery.
    """

    def __init__(self, enable_state_access_semantics: bool = True):
        super().__init__(
            enable_cross_contract_path_recovery=False,
            enable_state_access_semantics=enable_state_access_semantics,
        )

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

            for target_key in target_keys:
                entry_id = self.function_entries.get(target_key)
                if entry_id is None:
                    continue
                target_contract = target_key.split(".", 1)[0]
                if source_node and target_contract != source_node.contract_name:
                    continue

                self.add_call_edge(source_id, entry_id)
                if return_target is not None:
                    for exit_id in self.get_function_exits(target_key):
                        self.add_return_edge(exit_id, return_target)
