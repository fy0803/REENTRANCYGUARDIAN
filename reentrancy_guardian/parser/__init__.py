"""
源码解析与标准化层 (Parser Layer)

职责：
1. 调用 Slither 解析 Solidity 项目
2. 提取合约、函数、状态变量、调用信息
3. 标准化输出中间表示

主要模块：
- slither_loader: Slither 集成和加载
- contract_extractor: 合约和函数提取
- normalizer: 信息标准化
"""

from .slither_loader import SlitherLoader
from .contract_extractor import ContractExtractor
from .normalizer import Normalizer

__all__ = [
    'SlitherLoader',
    'ContractExtractor',
    'Normalizer',
]
