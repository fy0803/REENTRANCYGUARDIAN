"""
漏洞检测分析层 (Analysis Layer)

职责：
1. 跨合约重入 (CCR) 检测和路径分析
2. 只读重入 (ROR) 检测和模式匹配
3. 污点分析和数据流追踪

主要模块：
- ccr_detector: 跨合约重入关键路径分析
- ror_detector: 只读重入模式匹配
- taint_engine: 过程间污点传播引擎
- sink_rules: 关键汇点识别规则
"""

from .ccr_detector import CCRDetector
from .ror_detector import RORDetector
from .taint_engine import TaintEngine, EnhancedTaintAnalysis
from .sink_rules import SinkRuleManager

__all__ = [
    'CCRDetector',
    'RORDetector',
    'TaintEngine',
    'EnhancedTaintAnalysis',
    'SinkRuleManager',
]
