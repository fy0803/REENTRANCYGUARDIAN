#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MismatchWindow & LockScope - 状态失配窗口和锁保护域

论文中ICFG构建的两个关键语义增强概念。
"""

from typing import Set, List, Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class MismatchWindow:
    """
    状态失配窗口 (State Mismatch Window)
    
    定义：从外部调用前的状态 → 外部调用 → 外部调用后的状态
    用于检测状态在外部调用前后的不匹配，这是只读重入的基础。
    """
    window_id: str  # 唯一标识
    contract_name: str
    function_name: str
    
    # 窗口边界
    start_node_id: int  # 外部调用前的最后一个修改节点
    external_call_node_id: int  # 外部调用节点
    end_node_id: int  # 外部调用后的第一个使用节点
    
    # 状态变量信息
    pre_updated_states: Set[str] = field(default_factory=set)  # 调用前更新的状态
    post_updated_states: Set[str] = field(default_factory=set)  # 调用后更新的状态
    queried_states: Set[str] = field(default_factory=set)  # 可能被查询的状态
    
    # 元数据
    severity: str = "medium"  # 风险等级
    reason: str = ""  # 失配原因
    
    window_kind: str = "pre_post"

    def __hash__(self):
        return hash((self.window_id, self.contract_name, self.function_name))
    
    def __eq__(self, other):
        if not isinstance(other, MismatchWindow):
            return False
        return self.window_id == other.window_id
    
    def has_state_overlap(self, other: 'MismatchWindow') -> bool:
        """检查与另一个窗口是否有状态重叠"""
        overlap = self.queried_states & (other.pre_updated_states | other.post_updated_states)
        return bool(overlap)
    
    def get_overlap_states(self, other: 'MismatchWindow') -> Set[str]:
        """获取与另一个窗口的重叠状态"""
        return self.queried_states & (other.pre_updated_states | other.post_updated_states)


@dataclass  
class LockScope:
    """
    锁保护域 (Lock Scope)
    
    定义：被某个锁（如mutex、reentrant guard等）保护的代码路径集合
    用于排除已被有效保护的路由，减少误报。
    """
    lock_id: str  # 唯一标识（对应的lock variable或modifier）
    contract_name: str
    function_name: str
    
    # 覆盖的节点范围
    covered_node_ids: Set[int] = field(default_factory=set)
    
    # 锁的类型和属性
    lock_type: str = "unknown"  # "mutex", "reentrant_guard", "nonreentrant", etc.
    lock_variable: Optional[str] = None  # 对应的状态变量或modifier名称
    
    # 防护规则
    protected_states: Set[str] = field(default_factory=set)  # 该锁保护的状态变量
    
    # 元数据
    start_node_id: Optional[int] = None
    end_node_id: Optional[int] = None
    
    def __hash__(self):
        return hash((self.lock_id, self.contract_name, self.function_name))
    
    def __eq__(self, other):
        if not isinstance(other, LockScope):
            return False
        return self.lock_id == other.lock_id
    
    def covers_node(self, node_id: int) -> bool:
        """检查该锁是否保护了指定节点"""
        return node_id in self.covered_node_ids
    
    def covers_path(self, node_ids: List[int]) -> bool:
        """检查该锁是否保护了整个路径"""
        return all(node_id in self.covered_node_ids for node_id in node_ids)
    
    def protects_state(self, state_var: str) -> bool:
        """检查该锁是否保护了指定状态变量"""
        return state_var in self.protected_states
