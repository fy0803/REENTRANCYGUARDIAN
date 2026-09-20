#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class NodeInfo:
    """Normalized semantic node used by the enhanced ICFG."""

    node_id: int
    contract_name: str
    function_name: str

    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)

    call_type: Optional[str] = None
    call_target_contract: Optional[str] = None
    call_target_function: Optional[str] = None
    call_targets: List[str] = field(default_factory=list)

    node_type: str = ""
    source_node_id: Optional[int] = None
    visibility: Optional[str] = None
    state_mutability: Optional[str] = None
    modifiers: List[str] = field(default_factory=list)
    expression: str = ""
    irs: List[str] = field(default_factory=list)
    ir_types: List[str] = field(default_factory=list)

    in_lock_scope: bool = False
    lock_id: Optional[str] = None
    readonly_context: bool = False
    exec_owner: Optional[str] = None
    storage_host: Optional[str] = None

    location: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.node_id, self.contract_name, self.function_name))

    @property
    def function_key(self) -> str:
        return f"{self.contract_name}.{self.function_name}"

    def has_state_read(self, state_var: str) -> bool:
        return state_var in self.reads

    def has_state_write(self, state_var: str) -> bool:
        return state_var in self.writes

    def has_state_access(self) -> bool:
        return bool(self.reads or self.writes)

    def is_external_call(self) -> bool:
        return self.call_type in {
            "high_level_call",
            "low_level_call",
            "call",
            "delegatecall",
            "staticcall",
            "callcode",
        }

    def is_reentrancy_sink(self) -> bool:
        return self.call_type in {"high_level_call", "low_level_call", "call", "delegatecall"}

    def is_delegatecall(self) -> bool:
        return self.call_type == "delegatecall"

    def is_staticcall(self) -> bool:
        return self.call_type == "staticcall"

    def overlaps_states(self, other: "NodeInfo") -> Set[str]:
        return (self.reads | self.writes) & (other.reads | other.writes)
