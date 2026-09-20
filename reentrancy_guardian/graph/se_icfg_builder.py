#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict, List

from .icfg_builder import ICFGBuilder
from .intracontract_cfg_builder import IntraContractCFGBuilder
from .lock_scope import LockScopeAnalyzer
from .mismatch_window import MismatchWindowDetector
from .semantic_edges import SemanticEdgeAnalyzer


class SEICFGBuilder:
    """
    Build a semantic-enhanced ICFG in two stages:
    1. Inter-contract CFG stitching across caller/callee boundaries.
    2. Semantic edge augmentation for reentrancy analysis.
    """

    def __init__(
        self,
        *,
        enable_callback_edges: bool = True,
        enable_cross_contract_path_recovery: bool = True,
        enable_state_access_semantics: bool = True,
        enable_state_access_propagation: bool = True,
        intra_contract_only: bool = False,
        enable_lock_context: bool = True,
    ):
        if intra_contract_only:
            self.base_icfg = IntraContractCFGBuilder(
                enable_state_access_semantics=enable_state_access_semantics,
            )
        else:
            self.base_icfg = ICFGBuilder(
                enable_cross_contract_path_recovery=enable_cross_contract_path_recovery,
                enable_state_access_semantics=enable_state_access_semantics,
            )
        self.enable_callback_edges = enable_callback_edges
        self.enable_state_access_propagation = enable_state_access_propagation
        self.intra_contract_only = intra_contract_only
        self.enable_lock_context = enable_lock_context
        self.semantic: SemanticEdgeAnalyzer | None = None
        self.lock: LockScopeAnalyzer | None = None
        self.mismatch: MismatchWindowDetector | None = None
        self.contracts_info: Dict[str, Any] = {}

    def build_from_contracts(
        self,
        contracts: List[Any],
        contracts_info: Dict[str, Any],
        normalized_nodes: Dict[int, Any] | None = None,
    ) -> "SEICFGBuilder":
        self.contracts_info = contracts_info

        # Stage 1: stitch caller/callee CFGs into an inter-contract ICFG.
        self.base_icfg.build_from_contracts(contracts, normalized_nodes=normalized_nodes)

        # Stage 2: semantic enhancement to form the SE-ICFG.
        self.semantic = SemanticEdgeAnalyzer(self.base_icfg, contracts_info)
        if self.enable_callback_edges:
            self.semantic.analyze_callback_edges()
        self.semantic.analyze_readonly_edges()
        self.semantic.analyze_alias_edges()

        if self.enable_lock_context:
            self.lock = LockScopeAnalyzer(self.base_icfg, contracts_info)
            self.lock.detect_lock_variables()
            self.lock.analyze_lock_scopes()
        else:
            self.lock = None

        self.mismatch = MismatchWindowDetector(
            self.base_icfg,
            contracts_info,
            ablation_no_state_access_propagation=not self.enable_state_access_propagation,
        )
        self.mismatch.detect_windows()
        return self

    def get_statistics(self) -> Dict[str, Any]:
        stats = dict(self.base_icfg.get_statistics())
        stats.update(
            {
                "intra_contract_only": self.intra_contract_only,
                "inter_contract_callsites": len(self.base_icfg.get_inter_contract_callsites()),
                "callsites_with_followup": sum(
                    1 for followup in self.base_icfg.callsite_followups.values() if followup is not None
                ),
                "callback_edges": len(self.semantic.callback_edges) if self.semantic else 0,
                "readonly_edges": len(self.semantic.readonly_edges) if self.semantic else 0,
                "alias_edges": len(self.semantic.alias_edges) if self.semantic else 0,
                "lock_scopes": len(self.lock.lock_scopes) if self.lock else 0,
                "mismatch_windows": len(self.mismatch.mismatch_windows) if self.mismatch else 0,
            }
        )
        return stats

    def describe_callsites(self) -> Dict[int, Dict[str, Any]]:
        result: Dict[int, Dict[str, Any]] = {}
        for node_id in self.base_icfg.get_inter_contract_callsites():
            node = self.base_icfg.nodes.get(node_id)
            if not node:
                continue
            result[node_id] = {
                "function": node.function_key,
                "call_type": node.call_type,
                "callee_entries": self.base_icfg.get_callsite_callee_entries(node_id),
                "callee_exits": self.base_icfg.get_callsite_callee_exits(node_id),
                "followup": self.base_icfg.get_callsite_followup(node_id),
                "semantic_targets": sorted(self.base_icfg.get_semantic_successors(node_id)),
            }
        return result
