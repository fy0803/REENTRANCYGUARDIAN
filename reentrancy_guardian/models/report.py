#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnerabilityReport - 最终漏洞报告

论文中的检测结果统一输出格式。
"""

from typing import List, Set, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(Enum):
    """风险等级"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class VulnerabilityReport:
    """
    统一的漏洞报告格式
    
    每条结果包含：
    - 基本信息：编号、类型、风险等级
    - 涉及对象：合约、函数、状态变量
    - 证据链：外部调用点、回调入口、查询节点、汇点
    - 判定理由：路径、污染链、代码位置
    """
    
    # 基本信息
    vuln_id: str  # 唯一标识
    vuln_type: str  # user-facing label
    severity: str  # "High", "Medium", "Low"
    
    # 涉及的合约和函数
    source_contract: str
    source_function: str
    vuln_family: str = ""  # "CCR" or "ROR"
    target_contract: Optional[str] = None
    target_function: Optional[str] = None
    
    # 关键对象
    key_states: Set[str] = field(default_factory=set)  # 关键状态变量
    external_call: Optional[Dict[str, Any]] = None  # 外部调用信息
    callback_entry: Optional[Dict[str, Any]] = None  # 回调入口信息
    
    # 特定于 CCR 的字段
    overlap_states: Set[str] = field(default_factory=set)
    
    # 特定于 ROR 的字段
    mismatch_window: Optional[Dict[str, Any]] = None  # 失配窗口
    query_function: Optional[str] = None  # 查询函数
    query_node: Optional[Dict[str, Any]] = None  # 查询节点
    sink_function: Optional[str] = None  # 汇点函数
    sink_node: Optional[Dict[str, Any]] = None  # 汇点节点
    propagation_path: List[int] = field(default_factory=list)  # 污染传播路径
    
    # 证据和判定
    evidence_path: List[Dict[str, Any]] = field(default_factory=list)  # 关键路径或传播链
    reason: str = ""  # 漏洞判定理由
    code_locations: Dict[str, Any] = field(default_factory=dict)  # 代码位置信息
    
    # 评分信息
    confidence_score: float = 0.5  # 置信度
    potential_impact: str = ""  # 潜在影响描述
    
    def __hash__(self):
        return hash(self.vuln_id)
    
    def __eq__(self, other):
        if not isinstance(other, VulnerabilityReport):
            return False
        return self.vuln_id == other.vuln_id
    
    def is_ccr(self) -> bool:
        """检查是否为 CCR 漏洞"""
        return self.vuln_family == "CCR" or self.vuln_type in {"CCR", "Classic Reentrancy", "Cross-Contract Reentrancy"}
    
    def is_ror(self) -> bool:
        """检查是否为 ROR 漏洞"""
        return self.vuln_family == "ROR" or self.vuln_type == "ROR"

    def display_type(self) -> str:
        if self.vuln_type in {"CCR", "ROR"} and self.vuln_family:
            return self.vuln_family
        return self.vuln_type
    
    def get_summary(self) -> str:
        """获取简短的漏洞摘要"""
        if self.is_ccr():
            return f"{self.display_type()} in {self.source_contract}.{self.source_function}() " \
                   f"calls {self.target_contract}.{self.target_function}()"
        else:  # ROR
            return f"{self.display_type()} in {self.source_contract}.{self.source_function}() " \
                   f"via {self.query_function}() -> {self.sink_function}()"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'vuln_id': self.vuln_id,
            'vuln_type': self.vuln_type,
            'vuln_family': self.vuln_family,
            'severity': self.severity,
            'source_contract': self.source_contract,
            'source_function': self.source_function,
            'target_contract': self.target_contract,
            'target_function': self.target_function,
            'key_states': list(self.key_states),
            'query_function': self.query_function,
            'sink_function': self.sink_function,
            'reason': self.reason,
            'confidence': self.confidence_score,
        }
