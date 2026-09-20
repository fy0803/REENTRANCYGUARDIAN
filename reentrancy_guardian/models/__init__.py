"""
数据模型层 - 定义论文中的核心数据结构

包含：
- NodeInfo: 程序节点属性
- MismatchWindow: 状态失配窗口
- LockScope: 锁保护域
- CCRCandidate: 跨合约重入候选
- RORCandidate: 只读重入候选
- VulnerabilityReport: 最终漏洞报告
"""

from .node_info import NodeInfo
from .window import MismatchWindow, LockScope
from .candidate import CCRCandidate, RORCandidate
from .report import VulnerabilityReport

__all__ = [
    'NodeInfo',
    'MismatchWindow',
    'LockScope',
    'CCRCandidate',
    'RORCandidate',
    'VulnerabilityReport',
]
