"""
程序表示构建层 (Graph Layer)

职责：
1. 构建语义增强型 ICFG (Enhanced ICFG)
2. 识别语义增强边 (回调边、只读依赖边、存储别名边)
3. 标记锁保护域
4. 提取状态失配窗口

主要模块：
- icfg_builder: ICFG 基础构建
- semantic_edges: 语义增强边 (回调、只读、别名)
- lock_scope: 锁保护域识别和标记
- mismatch_window: 状态失配窗口提取
"""

from .icfg_builder import ICFGBuilder
from .se_icfg_builder import SEICFGBuilder
from .semantic_edges import SemanticEdgeAnalyzer
from .lock_scope import LockScopeAnalyzer
from .mismatch_window import MismatchWindowDetector

__all__ = [
    'ICFGBuilder',
    'SEICFGBuilder',
    'SemanticEdgeAnalyzer',
    'LockScopeAnalyzer',
    'MismatchWindowDetector',
]
