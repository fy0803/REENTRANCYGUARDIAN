#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scorer - 风险评分和等级判定

负责：
1. 计算各种评分维度（路径、流、影响、保护）
2. 综合评分转换为风险等级
3. 生成最终的严重程度等级
"""

from typing import Dict, Any, Tuple
from enum import Enum
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import CCRCandidate, RORCandidate, VulnerabilityReport


class SeverityLevel(Enum):
    """严重程度等级"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Scorer:
    """漏洞风险评分器"""
    
    # 评分参数（论文或实践中的经验值）
    SCORE_WEIGHTS = {
        'path_score': 0.25,
        'flow_score': 0.25,
        'impact_score': 0.35,
        'protect_score': 0.15,
    }
    
    SEVERITY_THRESHOLDS = {
        'high': 0.7,      # >= 0.7 为 High
        'medium': 0.4,    # >= 0.4 为 Medium
        'low': 0.0,       # >= 0.0 为 Low
    }
    
    def __init__(self):
        """初始化评分器"""
        pass
    
    def score_ccr(self, candidate: CCRCandidate) -> Tuple[float, str]:
        """
        评分 CCR 候选
        
        评分维度：
        1. 路径评分 (path_score): 基于路径长度、复杂度、可达性
        2. 流评分 (flow_score): 基于状态冲突类型、冲突数量
        3. 影响评分 (impact_score): 基于涉及的状态变量敏感程度
        4. 保护评分 (protect_score): 基于锁保护、条件检查等防护机制
        
        Returns:
            (综合评分, 严重程度等级)
        """
        path_score = self._calculate_path_score(candidate)
        flow_score = self._calculate_flow_score_ccr(candidate)
        impact_score = self._calculate_impact_score(candidate)
        protect_score = self._calculate_protect_score_ccr(candidate)
        
        composite_score = (
            self.SCORE_WEIGHTS['path_score'] * path_score +
            self.SCORE_WEIGHTS['flow_score'] * flow_score +
            self.SCORE_WEIGHTS['impact_score'] * impact_score +
            self.SCORE_WEIGHTS['protect_score'] * protect_score
        )
        
        severity = self._score_to_severity(composite_score)
        return composite_score, severity
    
    def score_ror(self, candidate: RORCandidate) -> Tuple[float, str]:
        """
        评分 ROR 候选
        
        评分维度：
        1. 路径评分 (path_score): 基于污染传播路径
        2. 流评分 (flow_score): 基于污染链的确定性
        3. 影响评分 (impact_score): 基于汇点的关键性
        4. 保护评分 (protect_score): 基于现有的缓解机制
        
        Returns:
            (综合评分, 严重程度等级)
        """
        path_score = self._calculate_propagation_path_score(candidate)
        flow_score = self._calculate_flow_score_ror(candidate)
        impact_score = self._calculate_impact_score_ror(candidate)
        protect_score = self._calculate_protect_score_ror(candidate)
        
        composite_score = (
            self.SCORE_WEIGHTS['path_score'] * path_score +
            self.SCORE_WEIGHTS['flow_score'] * flow_score +
            self.SCORE_WEIGHTS['impact_score'] * impact_score +
            self.SCORE_WEIGHTS['protect_score'] * protect_score
        )
        
        severity = self._score_to_severity(composite_score)
        return composite_score, severity
    
    def _calculate_path_score(self, candidate: CCRCandidate) -> float:
        """
        计算 CCR 路径评分
        
        考虑因素：
        - 路径长度（越长越易被发现，评分越低）
        - 路径复杂度（分支点）
        - 路径中外部调用的数量
        """
        path_len = len(candidate.path_node_ids)
        if path_len <= 1:
            return 0.9
        if path_len <= 3:
            return 0.8
        if path_len <= 6:
            return 0.65
        return 0.5
    
    def _calculate_flow_score_ccr(self, candidate: CCRCandidate) -> float:
        """计算 CCR 的流评分（状态冲突的确定性）"""
        overlap_count = len(candidate.overlap_states)
        base = 0.5
        if overlap_count >= 3:
            base += 0.25
        elif overlap_count >= 1:
            base += 0.15

        if candidate.call_type and 'low' in candidate.call_type.lower():
            base += 0.1
        return min(1.0, base)
    
    def _calculate_flow_score_ror(self, candidate: RORCandidate) -> float:
        """计算 ROR 的流评分（污染确定性）"""
        overlap_count = len(candidate.overlap_states)
        query_count = len(candidate.query_return_states)
        shared = len(candidate.overlap_states & candidate.query_return_states)

        base = 0.45
        base += min(0.25, overlap_count * 0.05)
        base += min(0.2, query_count * 0.03)
        base += min(0.1, shared * 0.05)
        return min(1.0, base)
    
    def _calculate_impact_score(self, candidate: CCRCandidate) -> float:
        """计算 CCR 的影响评分（涉及的状态变量敏感性）"""
        sensitive_keywords = ('balance', 'amount', 'total', 'reserve', 'owner')
        states = {s.lower() for s in candidate.overlap_states}
        if not states:
            return 0.4

        sensitive_hits = sum(
            1 for s in states if any(keyword in s for keyword in sensitive_keywords)
        )
        ratio = sensitive_hits / max(1, len(states))
        return min(1.0, 0.45 + ratio * 0.5)
    
    def _calculate_impact_score_ror(self, candidate: RORCandidate) -> float:
        """计算 ROR 的影响评分（汇点函数的关键性）"""
        sink_name = (candidate.sink_function or '').lower()
        critical_keywords = ('swap', 'liquidate', 'borrow', 'withdraw', 'mint', 'redeem')
        if any(keyword in sink_name for keyword in critical_keywords):
            return 0.9
        if sink_name:
            return 0.65
        return 0.45
    
    def _calculate_protect_score_ccr(self, candidate: CCRCandidate) -> float:
        """计算 CCR 的保护评分（1 - 防护强度）"""
        if candidate.lock_blocked:
            return 0.0  # 完全被保护
        return 1.0  # 没有保护
    
    def _calculate_protect_score_ror(self, candidate: RORCandidate) -> float:
        """计算 ROR 的保护评分"""
        if candidate.mitigated:
            return 0.0
        return 1.0
    
    def _calculate_propagation_path_score(self, candidate: RORCandidate) -> float:
        """计算污染传播路径评分"""
        path_len = len(candidate.propagation_path)
        if path_len == 0:
            return 0.5
        if path_len <= 2:
            return 0.85
        if path_len <= 5:
            return 0.75
        return 0.6
    
    def _score_to_severity(self, score: float) -> str:
        """将评分转换为严重程度等级"""
        if score >= self.SEVERITY_THRESHOLDS['high']:
            return SeverityLevel.HIGH.value
        elif score >= self.SEVERITY_THRESHOLDS['medium']:
            return SeverityLevel.MEDIUM.value
        else:
            return SeverityLevel.LOW.value
