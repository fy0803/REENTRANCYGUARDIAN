#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class VulnerabilityType(Enum):
    CCR = "Cross-Contract Reentrancy"
    ROR = "Read-Only Reentrancy"


@dataclass
class CCRCandidate:
    """Candidate for classic or cross-contract reentrancy."""

    candidate_id: str

    source_contract: str
    entry_function: str

    external_call_node: int
    call_type: str = "unknown"

    target_contract: Optional[str] = None
    callback_entry_function: Optional[str] = None
    # `callback_kind` is set by the detector when we have a precise callback edge.
    # When unset, we fall back to the older source/target-contract heuristic.
    callback_kind: Optional[str] = None

    overlap_states: Set[str] = field(default_factory=set)
    path_node_ids: List[int] = field(default_factory=list)

    lock_blocked: bool = False
    lock_id: Optional[str] = None

    reason: str = ""
    confidence: float = 0.5

    def classification_label(self) -> str:
        if self.callback_kind == "cross_contract":
            return "Cross-Contract Reentrancy"
        if self.callback_kind in {"classic", "classic_resolved"}:
            return "Classic Reentrancy"
        return "Cross-Contract Reentrancy" if self.is_cross_contract() else "Classic Reentrancy"

    def __hash__(self):
        return hash(self.candidate_id)

    def __eq__(self, other):
        if not isinstance(other, CCRCandidate):
            return False
        return self.candidate_id == other.candidate_id

    def is_valid(self) -> bool:
        return bool(self.entry_function and self.external_call_node >= 0 and self.overlap_states)

    def is_cross_contract(self) -> bool:
        if self.callback_kind == "cross_contract":
            return True
        if self.callback_kind in {"classic", "classic_resolved"}:
            return False
        return self.source_contract != self.target_contract


@dataclass
class RORCandidate:
    """Candidate for read-only reentrancy."""

    candidate_id: str

    contract_name: str
    window_function: str

    window_id: str
    start_node_id: int
    external_call_node_id: int
    end_node_id: int

    query_function: str
    query_return_states: Set[str] = field(default_factory=set)

    sink_function: Optional[str] = None
    sink_node_ids: List[int] = field(default_factory=list)

    overlap_states: Set[str] = field(default_factory=set)

    propagation_path: List[int] = field(default_factory=list)
    tainted_query_vars: Set[str] = field(default_factory=set)
    tainted_sink_vars: Set[str] = field(default_factory=set)
    tainted_constraint_vars: Set[str] = field(default_factory=set)
    tainted_consumed_by_node: Dict[int, Set[str]] = field(default_factory=dict)

    mitigated: bool = False
    mitigation_reason: str = ""

    reason: str = ""
    confidence: float = 0.5
    external_sink: bool = False

    def __hash__(self):
        return hash(self.candidate_id)

    def __eq__(self, other):
        if not isinstance(other, RORCandidate):
            return False
        return self.candidate_id == other.candidate_id

    def is_valid(self) -> bool:
        return bool(self.window_function and self.query_function and self.overlap_states)

    def has_propagation(self) -> bool:
        return bool(self.propagation_path)
