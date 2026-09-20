#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reentrancy Guardian - 配置文件

包含系统参数、默认设置和可调参数
"""

from typing import Dict, Any, List


class Config:
    """系统配置"""
    
    # ==================== 基础配置 ====================
    
    # 项目信息
    PROJECT_NAME = "Reentrancy Guardian"
    PROJECT_VERSION = "0.1.0"
    PROJECT_DESCRIPTION = "Cross-Contract Reentrancy and Read-Only Reentrancy Detector"
    
    # ==================== 分析参数 ====================
    
    # 是否启用的功能
    ENABLE_CCR_ANALYSIS = True  # 跨合约重入检测
    ENABLE_ROR_ANALYSIS = True  # 只读重入检测
    ENABLE_ALIAS_ANALYSIS = False  # 别名分析（高级，可选）
    ENABLE_CONTEXT_SENSITIVE = False  # 上下文敏感分析（高级，可选）
    ENABLE_PRECISION_FILTERS = True
    ENABLE_CLASSIC_FALLBACK = True
    CLASSIC_FALLBACK_POLICY = "strict_v6"
    CLASSIC_FALLBACK_POLICY_CHOICES = ("normal", "strict", "strict_v6", "strict-v6", "aggressive", "off")
    CLASSIC_FALLBACK_POLICY_ALIASES = {
        "strict_v6": "strict",
        "strict-v6": "strict",
    }
    
    # 污点分析配置
    TAINT_DEPTH_LIMIT = 100  # 污染传播深度限制
    TAINT_PATH_LIMIT = 1000  # 污染路径数量限制
    
    # 路径分析配置
    PATH_DEPTH_LIMIT = 50  # 路径搜索深度限制
    PATH_BREADTH_LIMIT = 100  # 路径分支限制
    
    # ==================== 评分参数 ====================
    
    # 风险评分权重（总和应为1.0）
    SCORE_WEIGHTS = {
        'path_score': 0.25,      # 路径复杂度权重
        'flow_score': 0.25,      # 数据流权重
        'impact_score': 0.35,    # 影响权重
        'protect_score': 0.15,   # 保护机制权重
    }
    
    # 严重程度阈值
    SEVERITY_THRESHOLDS = {
        'high': 0.7,    # >= 0.7 为 High
        'medium': 0.4,  # >= 0.4 为 Medium
        'low': 0.0,     # >= 0.0 为 Low
    }
    
    # ==================== 输出配置 ====================
    
    # 输出格式选项
    OUTPUT_FORMATS = ['json', 'csv', 'console']
    DEFAULT_OUTPUT_FORMAT = 'json'
    
    # 输出文件配置
    OUTPUT_DIR = './results'
    OUTPUT_JSON_FILE = 'vulnerabilities.json'
    OUTPUT_CSV_FILE = 'vulnerabilities.csv'
    
    # 详细程度
    VERBOSE = False
    DETAILED_REPORT = True
    
    # ==================== 编译器配置 ====================
    
    # Solidity 编译器配置
    SOLC_VERSION = None  # 自动检测，或指定具体版本如 "0.8.0"
    
    # 编译优化级别
    OPTIMIZE = True
    OPTIMIZE_RUNS = 200
    
    # ==================== 超时配置 ====================
    
    # 分析超时（秒）
    ANALYSIS_TIMEOUT = 300
    
    # 单个函数分析超时
    FUNCTION_TIMEOUT = 30

    # Optional bounded CCR mode for large-contract coverage diagnostics.
    # None keeps the default analysis exact.
    CCR_STATE_LIMIT = None
    CCR_TIME_BUDGET = None
    
    # ==================== Slither 配置 ====================
    
    SLITHER_ARGS = {}  # 传递给 Slither 的额外参数
    
    # ==================== 缓存配置 ====================
    
    # 是否使用缓存
    USE_CACHE = True
    CACHE_DIR = './.cache'
    
    @classmethod
    def get_output_paths(cls) -> Dict[str, str]:
        """获取所有输出文件路径"""
        import os
        os.makedirs(cls.OUTPUT_DIR, exist_ok=True)
        
        return {
            'json': os.path.join(cls.OUTPUT_DIR, cls.OUTPUT_JSON_FILE),
            'csv': os.path.join(cls.OUTPUT_DIR, cls.OUTPUT_CSV_FILE),
        }
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """将配置转为字典"""
        return {
            'project': {
                'name': cls.PROJECT_NAME,
                'version': cls.PROJECT_VERSION,
            },
            'analysis': {
                'ccr': cls.ENABLE_CCR_ANALYSIS,
                'ror': cls.ENABLE_ROR_ANALYSIS,
                'alias': cls.ENABLE_ALIAS_ANALYSIS,
            },
            'limits': {
                'taint_depth': cls.TAINT_DEPTH_LIMIT,
                'path_depth': cls.PATH_DEPTH_LIMIT,
            },
            'scoring': {
                'weights': cls.SCORE_WEIGHTS,
                'thresholds': cls.SEVERITY_THRESHOLDS,
            }
        }


# ==================== 可覆盖的配置类 ====================

def normalize_classic_fallback_policy(policy: str) -> str:
    return Config.CLASSIC_FALLBACK_POLICY_ALIASES.get(policy, policy)


class AnalysisConfig:
    """分析时的可配置参数"""
    
    def __init__(self):
        self.enable_ccr = Config.ENABLE_CCR_ANALYSIS
        self.enable_ror = Config.ENABLE_ROR_ANALYSIS
        self.enable_alias = Config.ENABLE_ALIAS_ANALYSIS
        self.enable_context_sensitive = Config.ENABLE_CONTEXT_SENSITIVE
        self.enable_precision_filters = Config.ENABLE_PRECISION_FILTERS
        self.enable_classic_fallback = Config.ENABLE_CLASSIC_FALLBACK
        self.classic_fallback_policy_label = Config.CLASSIC_FALLBACK_POLICY
        self.classic_fallback_policy = normalize_classic_fallback_policy(Config.CLASSIC_FALLBACK_POLICY)
        self.ablation_no_icfg_modeling = False
        self.ablation_no_se_icfg_modeling_strict = False
        self.ablation_no_semantic_enhancement = False
        self.ablation_intra_contract_only = False
        self.ablation_no_callback_edges = False
        self.ablation_no_cross_contract_path_recovery = False
        self.ablation_no_state_access_semantics = False
        self.ablation_no_state_access_propagation = False
        self.ablation_explicit_state_conflict_only = False
        self.ablation_no_state_conflict = False
        self.ablation_no_lock_context = False
        self.ablation_no_path_constraints = False
        self.ablation_no_ror_mismatch_window = False
        self.ablation_no_ror_propagation = False
        self.ablation_no_ror_sensitive_sink = False
        
        self.taint_depth_limit = Config.TAINT_DEPTH_LIMIT
        self.path_depth_limit = Config.PATH_DEPTH_LIMIT
        
        self.timeout = Config.ANALYSIS_TIMEOUT
        self.ccr_state_limit = Config.CCR_STATE_LIMIT
        self.ccr_time_budget = Config.CCR_TIME_BUDGET
        self.verbose = Config.VERBOSE


if __name__ == '__main__':
    # 打印默认配置
    import json
    print(json.dumps(Config.to_dict(), indent=2, ensure_ascii=False))
