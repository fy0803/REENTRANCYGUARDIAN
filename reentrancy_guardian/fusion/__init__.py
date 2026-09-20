"""
结果融合与判定层 (Fusion & Judgment Layer)

职责：
1. 验证 CCR 和 ROR 候选的有效性
2. 合并重复或相似结果
3. 计算风险评分
4. 生成最终漏洞报告

主要模块：
- validator: CCR/ROR 有效性验证
- merger: 结果合并和去重
- scorer: 风险评分和等级判定
"""

from .validator import Validator
from .merger import Merger
from .scorer import Scorer

__all__ = [
    'Validator',
    'Merger',
    'Scorer',
]
