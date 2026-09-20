#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from analysis.ccr_detector import CCRDetector
from analysis.ror_detector import RORDetector
from analysis.sink_rules import SinkRuleManager
from analysis.taint_engine import TaintEngine
from config import AnalysisConfig, Config, normalize_classic_fallback_policy
from fusion.merger import Merger
from fusion.report_filter import PrecisionFilter
from fusion.scorer import Scorer
from fusion.validator import Validator
from graph.intraprocedural_cfg_builder import IntraproceduralCFGBuilder
from graph.se_icfg_builder import SEICFGBuilder
from models.report import VulnerabilityReport
from parser.contract_extractor import ContractExtractor
from parser.normalizer import Normalizer
from parser.slither_loader import SlitherLoader
from report.csv_writer import CSVReportWriter
from report.json_writer import JSONReportWriter
from report.printer import ConsolePrinter


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def resolve_output_formats(json_requested: bool, csv_requested: bool):
    if json_requested or csv_requested:
        return json_requested, csv_requested
    return True, False


def resolve_output_targets(output_path: str = None, write_json: bool = True, write_csv: bool = False):
    if not write_json and not write_csv:
        return {}

    destination = Path(output_path) if output_path else Path(Config.OUTPUT_DIR)
    suffix = destination.suffix.lower()

    if suffix in {".json", ".csv"}:
        destination.parent.mkdir(parents=True, exist_ok=True)
        targets = {}
        if write_json:
            targets["json"] = destination if suffix == ".json" else destination.with_suffix(".json")
        if write_csv:
            targets["csv"] = destination if suffix == ".csv" else destination.with_suffix(".csv")
        return targets

    destination.mkdir(parents=True, exist_ok=True)
    targets = {}
    if write_json:
        targets["json"] = destination / Config.OUTPUT_JSON_FILE
    if write_csv:
        targets["csv"] = destination / Config.OUTPUT_CSV_FILE
    return targets


class NoopSemanticAnalyzer:
    def __init__(self):
        self.callback_edges = []
        self.readonly_edges = []
        self.alias_edges = []


class NoopMismatchWindowDetector:
    def __init__(self):
        self.mismatch_windows = {}

    def detect_windows(self):
        return {}


class NoICFGAblationModel:
    def __init__(self, builder):
        self.base_icfg = builder
        self.semantic = NoopSemanticAnalyzer()
        self.lock = None
        self.mismatch = NoopMismatchWindowDetector()

    def get_statistics(self):
        stats = dict(self.base_icfg.get_statistics())
        stats.update(
            {
                "ablation_no_icfg_modeling": True,
                "inter_contract_callsites": 0,
                "callsites_with_followup": 0,
                "callback_edges": 0,
                "readonly_edges": 0,
                "alias_edges": 0,
                "lock_scopes": 0,
                "mismatch_windows": 0,
            }
        )
        return stats


class ReentrancyGuardian:
    def __init__(self, config: AnalysisConfig = None):
        self.config = config or AnalysisConfig()
        self.printer = ConsolePrinter(verbose=self.config.verbose)

        self.parser = None
        self.icfg = None
        self.ccr_detector = None
        self.ror_detector = None
        self.taint_engine = None
        self.validator = None
        self.merger = None
        self.scorer = None

    def _path_solver_timeout_ms(self) -> int:
        timeout_seconds = max(1, int(getattr(self.config, "timeout", Config.ANALYSIS_TIMEOUT)))
        return timeout_seconds * 1000

    def _create_validator(self) -> Validator:
        no_semantic_enhancement = getattr(self.config, "ablation_no_semantic_enhancement", False)
        return Validator(
            self.icfg["builder"],
            self.icfg["lock"],
            self.taint_engine,
            path_timeout_ms=self._path_solver_timeout_ms(),
            ccr_state_limit=getattr(self.config, "ccr_state_limit", None),
            ablation_no_state_conflict=getattr(self.config, "ablation_no_state_conflict", False),
            ablation_no_lock_context=getattr(self.config, "ablation_no_lock_context", False),
            ablation_no_path_constraints=getattr(self.config, "ablation_no_path_constraints", False),
            ablation_no_ror_propagation=(
                getattr(self.config, "ablation_no_ror_propagation", False)
                or no_semantic_enhancement
            ),
            ablation_no_ror_sensitive_sink=getattr(self.config, "ablation_no_ror_sensitive_sink", False),
            ablation_no_state_access_propagation=getattr(
                self.config, "ablation_no_state_access_propagation", False
            ),
            ablation_explicit_state_conflict_only=getattr(
                self.config, "ablation_explicit_state_conflict_only", False
            ),
        )

    def analyze(self, target_path: str) -> dict:
        self.printer.print_header()

        try:
            self.printer.print_progress("Phase 1: Parsing", 0, 4)
            self._phase_parse(target_path)
            self.printer.print_progress("Phase 1: Parsing", 1, 4)

            self.printer.print_progress("Phase 2: ICFG Building", 1, 4)
            self._phase_icfg_building()
            self.printer.print_progress("Phase 2: ICFG Building", 2, 4)

            self.printer.print_progress("Phase 3: Detection", 2, 4)
            ccr_candidates, ror_candidates = self._phase_detection()
            self.printer.print_progress("Phase 3: Detection", 3, 4)

            self.printer.print_progress("Phase 4: Fusion & Reporting", 3, 4)
            results = self._phase_fusion(ccr_candidates, ror_candidates)
            self.printer.print_progress("Phase 4: Fusion & Reporting", 4, 4)
            return results
        except Exception as exc:
            self.printer.print_error(f"Analysis failed: {exc}")
            if self.config.verbose:
                import traceback

                traceback.print_exc()
            raise

    def _phase_parse(self, target_path: str):
        logging.info(f"Loading Solidity project from: {target_path}")

        loader = SlitherLoader()
        slither = loader.load_project(target_path)

        extractor = ContractExtractor(slither)
        contracts_info = extractor.extract_all()

        normalizer = Normalizer()
        normalized = normalizer.normalize_nodes(contracts_info)

        self.parser = {
            "slither": slither,
            "contracts_info": contracts_info,
            "normalized_nodes": normalized,
        }

    def _phase_icfg_building(self):
        if getattr(self.config, "ablation_no_semantic_enhancement", False):
            logging.info("Building intraprocedural CFG only for no-semantic-enhancement ablation...")
            local_builder = IntraproceduralCFGBuilder(strip_delegatecall_storage_ownership=True)
            local_builder.build_from_contracts(
                self.parser["slither"].contracts,
                normalized_nodes=self.parser.get("normalized_nodes"),
            )
            self.icfg = {
                "se_builder": NoICFGAblationModel(local_builder),
                "builder": local_builder,
                "semantic": NoopSemanticAnalyzer(),
                "lock": None,
                "mismatch": NoopMismatchWindowDetector(),
            }
            logging.info(
                "No-semantic-enhancement ablation statistics: "
                f"{self.icfg['se_builder'].get_statistics()}"
            )
            return

        if (
            getattr(self.config, "ablation_no_icfg_modeling", False)
            or getattr(self.config, "ablation_no_se_icfg_modeling_strict", False)
        ):
            strict_no_se_icfg = getattr(self.config, "ablation_no_se_icfg_modeling_strict", False)
            logging.info("Building intraprocedural CFG only for no-SE-ICFG ablation...")
            local_builder = IntraproceduralCFGBuilder(
                strip_delegatecall_storage_ownership=strict_no_se_icfg
            )
            local_builder.build_from_contracts(
                self.parser["slither"].contracts,
                normalized_nodes=self.parser.get("normalized_nodes"),
            )
            self.icfg = {
                "se_builder": NoICFGAblationModel(local_builder),
                "builder": local_builder,
                "semantic": NoopSemanticAnalyzer(),
                "lock": None,
                "mismatch": NoopMismatchWindowDetector(),
            }
            logging.info(f"No-SE-ICFG ablation statistics: {self.icfg['se_builder'].get_statistics()}")
            return

        logging.info("Building semantic-enhanced ICFG...")
        se_builder = SEICFGBuilder(
            enable_callback_edges=not getattr(self.config, "ablation_no_callback_edges", False),
            enable_cross_contract_path_recovery=not getattr(
                self.config, "ablation_no_cross_contract_path_recovery", False
            ),
            enable_state_access_semantics=not getattr(
                self.config, "ablation_no_state_access_semantics", False
            ),
            enable_state_access_propagation=not getattr(
                self.config, "ablation_no_state_access_propagation", False
            ),
            intra_contract_only=getattr(self.config, "ablation_intra_contract_only", False),
            enable_lock_context=not getattr(self.config, "ablation_no_lock_context", False),
        )
        se_builder.build_from_contracts(
            self.parser["slither"].contracts,
            self.parser["contracts_info"],
            normalized_nodes=self.parser.get("normalized_nodes"),
        )

        self.icfg = {
            "se_builder": se_builder,
            "builder": se_builder.base_icfg,
            "semantic": se_builder.semantic,
            "lock": se_builder.lock,
            "mismatch": se_builder.mismatch,
        }

        logging.info(f"SE-ICFG Statistics: {se_builder.get_statistics()}")

    def _phase_detection(self):
        logging.info("Running vulnerability detection...")

        ccr_candidates = []
        ror_candidates = []
        self.taint_engine = None

        if self.config.verbose:
            icfg_stats = self.icfg["se_builder"].get_statistics()
            print(f"[DEBUG] SE-ICFG Statistics: {icfg_stats}")
            print(f"[DEBUG] Functions in ICFG: {list(self.icfg['builder'].functions.keys())}")
            print(f"[DEBUG] Total nodes: {len(self.icfg['builder'].nodes)}")

        if self.config.enable_ccr:
            logging.info("Executing classic/cross-contract reentrancy detection...")
            ccr_detector = CCRDetector(
                self.icfg["builder"],
                self.icfg["semantic"],
                self.icfg["lock"],
                state_limit=getattr(self.config, "ccr_state_limit", None),
                time_budget_seconds=getattr(self.config, "ccr_time_budget", None),
                enable_classic_fallback=getattr(self.config, "enable_classic_fallback", True),
                classic_fallback_policy=getattr(self.config, "classic_fallback_policy", "normal"),
                ablation_no_state_conflict=getattr(self.config, "ablation_no_state_conflict", False),
                ablation_no_state_access_propagation=getattr(
                    self.config, "ablation_no_state_access_propagation", False
                ),
                ablation_explicit_state_conflict_only=getattr(
                    self.config, "ablation_explicit_state_conflict_only", False
                ),
            )
            ccr_candidates = ccr_detector.detect() or []
            if getattr(ccr_detector, "truncated", False):
                logging.warning(
                    "Bounded CCR detection reached a configured state/time limit; results are reduced-precision."
                )
                print("[WARN] Bounded CCR detection reached a configured state/time limit; results are reduced-precision.")
            ccr_breakdown = Counter(
                candidate.classification_label() if hasattr(candidate, "classification_label") else "CCR"
                for candidate in ccr_candidates
            )
            logging.info(
                "Found %s reentrancy-family candidates (%s)",
                len(ccr_candidates),
                ", ".join(f"{label}: {count}" for label, count in sorted(ccr_breakdown.items())) or "none",
            )
            if self.config.verbose:
                print(
                    "[DEBUG] Found "
                    f"{len(ccr_candidates)} reentrancy-family candidates: "
                    + (", ".join(f"{label}={count}" for label, count in sorted(ccr_breakdown.items())) or "none")
                )

        if self.config.enable_ror:
            logging.info("Executing ROR detection...")
            self.taint_engine = TaintEngine(self.icfg["builder"], SinkRuleManager())
            no_semantic_enhancement = getattr(self.config, "ablation_no_semantic_enhancement", False)
            ror_detector = RORDetector(
                self.icfg["builder"],
                self.icfg["mismatch"],
                self.taint_engine,
                ablation_no_mismatch_window=(
                    getattr(self.config, "ablation_no_ror_mismatch_window", False)
                    or no_semantic_enhancement
                ),
                ablation_no_propagation=(
                    getattr(self.config, "ablation_no_ror_propagation", False)
                    or no_semantic_enhancement
                ),
                ablation_no_state_access_propagation=getattr(
                    self.config, "ablation_no_state_access_propagation", False
                ),
            )
            ror_candidates = ror_detector.detect() or []
            logging.info(f"Found {len(ror_candidates)} ROR candidates")
            if self.config.verbose:
                print(f"[DEBUG] Found {len(ror_candidates)} ROR candidates")

        return ccr_candidates, ror_candidates

    def _phase_fusion(self, ccr_candidates, ror_candidates):
        logging.info("Validating and merging results...")

        validator = self._create_validator()
        self.validator = validator

        ccr_vulns = []
        for candidate in ccr_candidates:
            is_valid, reason = validator.validate_ccr(candidate)
            if is_valid:
                ccr_vulns.append(candidate)
            else:
                logging.debug(f"Reentrancy-family candidate dropped: {reason}")

        ror_vulns = []
        for candidate in ror_candidates:
            is_valid, reason = validator.validate_ror(candidate)
            if is_valid:
                ror_vulns.append(candidate)
            else:
                logging.debug(f"ROR candidate dropped: {reason}")

        scorer = Scorer()
        all_reports = []

        for vuln in ccr_vulns:
            score, severity = scorer.score_ccr(vuln)
            all_reports.append(self._to_ccr_report(vuln, score, severity))

        for vuln in ror_vulns:
            score, severity = scorer.score_ror(vuln)
            all_reports.append(self._to_ror_report(vuln, score, severity))

        merger = Merger()
        all_reports = merger.merge_duplicate_vulnerabilities(all_reports)

        if getattr(self.config, "enable_precision_filters", True):
            precision_filter = PrecisionFilter(
                classic_fallback_policy=getattr(self.config, "classic_fallback_policy", "normal")
            )
            all_reports, dropped_reports = precision_filter.filter_reports(all_reports)
            if dropped_reports:
                logging.info(
                    "Precision filters suppressed %s low-signal findings",
                    len(dropped_reports),
                )
                for report, reason in dropped_reports:
                    logging.debug("Suppressed %s: %s", report.vuln_id, reason)

        ccr_report_breakdown = Counter(report.vuln_type for report in all_reports if report.is_ccr())
        logging.info(
            "Validated: %s total findings (%s, ROR: %s)",
            len(all_reports),
            ", ".join(f"{label}: {count}" for label, count in sorted(ccr_report_breakdown.items())) or "no reentrancy-family findings",
            len(ror_vulns),
        )

        self.printer.print_summary(all_reports)
        self.printer.print_vulnerabilities(all_reports)

        return {
            "ccr_vulnerabilities": ccr_vulns,
            "ror_vulnerabilities": ror_vulns,
            "all_reports": all_reports,
        }

    def _node_location(self, node_id: int) -> dict:
        builder = self.icfg.get("builder") if self.icfg else None
        node = builder.nodes.get(node_id) if builder else None
        if not node:
            return {"node_id": node_id}
        location = dict(node.location or {})
        return {
            "node_id": node_id,
            "contract": node.contract_name,
            "function": node.function_name,
            "line": location.get("line"),
            "file": location.get("file"),
            "expression": node.expression,
        }

    def _to_ccr_report(self, vuln, score: float, severity: str) -> VulnerabilityReport:
        vuln_label = vuln.classification_label() if hasattr(vuln, "classification_label") else "CCR"
        return VulnerabilityReport(
            vuln_id=vuln.candidate_id,
            vuln_type=vuln_label,
            severity=severity,
            vuln_family="CCR",
            source_contract=vuln.source_contract,
            source_function=vuln.entry_function,
            target_contract=vuln.target_contract,
            target_function=vuln.callback_entry_function,
            key_states=set(vuln.overlap_states),
            external_call=self._node_location(vuln.external_call_node),
            callback_entry={
                "function": vuln.callback_entry_function,
                "kind": getattr(vuln, "callback_kind", None),
            },
            overlap_states=set(vuln.overlap_states),
            evidence_path=[self._node_location(node_id) for node_id in vuln.path_node_ids],
            reason=vuln.reason or f"Potential {vuln_label.lower()}",
            confidence_score=score,
            potential_impact=(
                "Cross-contract state inconsistency"
                if vuln_label == "Cross-Contract Reentrancy"
                else "Repeated entry before local state is finalized"
            ),
        )

    def _to_ror_report(self, vuln, score: float, severity: str) -> VulnerabilityReport:
        return VulnerabilityReport(
            vuln_id=vuln.candidate_id,
            vuln_type="ROR",
            severity=severity,
            vuln_family="ROR",
            source_contract=vuln.contract_name,
            source_function=vuln.window_function,
            key_states=set(vuln.overlap_states),
            mismatch_window={
                "window_id": vuln.window_id,
                "start_node_id": vuln.start_node_id,
                "external_call_node_id": vuln.external_call_node_id,
                "end_node_id": vuln.end_node_id,
            },
            query_function=vuln.query_function,
            sink_function=vuln.sink_function,
            propagation_path=list(vuln.propagation_path),
            evidence_path=[self._node_location(node_id) for node_id in vuln.propagation_path],
            reason=vuln.reason or "Potential read-only reentrancy",
            confidence_score=score,
            potential_impact="Business logic may consume stale query result",
        )

    def generate_reports(
        self,
        results: dict,
        output_path: str = None,
        write_json: bool = True,
        write_csv: bool = False,
    ):
        all_reports = results.get("all_reports", [])
        targets = resolve_output_targets(output_path, write_json=write_json, write_csv=write_csv)

        if "json" in targets:
            json_writer = JSONReportWriter()
            json_writer.write_reports(all_reports, str(targets["json"]))
            logging.info(f"JSON report saved to: {targets['json']}")

        if "csv" in targets:
            csv_writer = CSVReportWriter()
            csv_writer.write_summary(all_reports, str(targets["csv"]))
            logging.info(f"CSV report saved to: {targets['csv']}")

        return targets


def main():
    parser = argparse.ArgumentParser(
        description="Reentrancy Guardian - Classic, Cross-Contract, and Read-Only Reentrancy Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s contracts/MyContract.sol
  %(prog)s /path/to/foundry/project -o results/
  %(prog)s contracts/ --csv --json
  %(prog)s contracts/ -o results/report.json
        """,
    )

    parser.add_argument("target", help="Solidity file or project directory")
    parser.add_argument("-o", "--output", help="Output directory or report file path (default: ./results)")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--csv", action="store_true", help="Generate CSV report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--ccr-only",
        action="store_true",
        help="Only detect classic/cross-contract reentrancy family findings",
    )
    parser.add_argument("--ror-only", action="store_true", help="Only detect ROR")
    parser.add_argument(
        "--no-precision-filter",
        action="store_true",
        help="Disable conservative false-positive suppression filters",
    )
    parser.add_argument(
        "--no-classic-fallback",
        action="store_true",
        help="Disable same-contract classic fallback callbacks and keep only precise CCR callbacks plus ROR.",
    )
    parser.add_argument(
        "--classic-fallback-policy",
        choices=Config.CLASSIC_FALLBACK_POLICY_CHOICES,
        default=Config.CLASSIC_FALLBACK_POLICY,
        help=(
            "Classic fallback handling: normal keeps default recall, strict_v6 (alias: strict/strict-v6) "
            "uses the tuned strict-v6 false-positive suppression, aggressive enables broader high-precision "
            "suppressions, off disables same-contract fallback callbacks."
        ),
    )
    parser.add_argument("--timeout", type=int, default=Config.ANALYSIS_TIMEOUT, help="Analysis timeout")
    parser.add_argument(
        "--ablation-no-icfg-modeling",
        action="store_true",
        help=(
            "Use only intraprocedural CFG nodes/edges and disable call/return stitching, "
            "semantic edges, lock scopes, and ROR mismatch-window modeling."
        ),
    )
    parser.add_argument(
        "--ablation-no-se-icfg-modeling-strict",
        action="store_true",
        help=(
            "Strict no-SE-ICFG ablation: use only intraprocedural CFG nodes/edges, "
            "disable semantic edges, lock scopes, mismatch windows, delegatecall storage "
            "ownership, and classic fallback callback compensation."
        ),
    )
    parser.add_argument(
        "--ablation-no-semantic-enhancement",
        action="store_true",
        help=(
            "Disable the SE-ICFG semantic enhancement layer: function call/return relations, "
            "cross-contract call recovery, external reentrant windows, mismatch windows, "
            "readonly propagation, lock scopes, and delegatecall storage ownership semantics."
        ),
    )
    parser.add_argument(
        "--ablation-intra-contract-only",
        action="store_true",
        help=(
            "Use function-local and same-contract call/return edges only; disable "
            "cross-contract call/return stitching and cross-contract callback recovery."
        ),
    )
    parser.add_argument(
        "--ablation-no-callback-edges",
        action="store_true",
        help=(
            "Disable SE-ICFG callback edge generation while keeping classic fallback "
            "callback handling controlled by the classic fallback policy."
        ),
    )
    parser.add_argument("--ablation-no-cross-contract-path-recovery", action="store_true")
    parser.add_argument(
        "--ablation-no-state-access-semantics",
        action="store_true",
        help="Disable extraction/injection of node-level state read/write dependencies.",
    )
    parser.add_argument(
        "--ablation-no-state-access-propagation",
        action="store_true",
        help=(
            "Keep node-level reads/writes but disable interprocedural state-access "
            "propagation through calls, callbacks, and read-only query inlining."
        ),
    )
    parser.add_argument(
        "--ablation-explicit-state-conflict-only",
        action="store_true",
        help=(
            "Require an explicit pre-write/post-access state overlap and disable "
            "loose post-write or implicit-balance state-conflict recovery."
        ),
    )
    parser.add_argument("--ablation-no-state-conflict", action="store_true")
    parser.add_argument("--ablation-no-lock-context", action="store_true")
    parser.add_argument("--ablation-no-path-constraints", action="store_true")
    parser.add_argument("--ablation-no-ror-mismatch-window", action="store_true")
    parser.add_argument("--ablation-no-ror-propagation", action="store_true")
    parser.add_argument("--ablation-no-ror-sensitive-sink", action="store_true")
    parser.add_argument(
        "--bounded-ccr",
        action="store_true",
        help="Enable reduced-precision CCR limits for large-contract coverage diagnostics.",
    )
    parser.add_argument(
        "--ccr-state-limit",
        type=int,
        help="Maximum execution states explored per CCR reachability query when bounded CCR is enabled.",
    )
    parser.add_argument(
        "--ccr-time-budget",
        type=int,
        help="Maximum seconds spent in CCR detection when bounded CCR is enabled.",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    write_json, write_csv = resolve_output_formats(args.json, args.csv)

    config = AnalysisConfig()
    config.verbose = args.verbose
    config.timeout = args.timeout
    config.classic_fallback_policy_label = args.classic_fallback_policy
    config.classic_fallback_policy = normalize_classic_fallback_policy(args.classic_fallback_policy)
    if args.bounded_ccr:
        config.ccr_state_limit = args.ccr_state_limit or 2000
        config.ccr_time_budget = args.ccr_time_budget or 60

    if args.ccr_only:
        config.enable_ror = False
    if args.ror_only:
        config.enable_ccr = False
    if args.no_precision_filter:
        config.enable_precision_filters = False
    if args.no_classic_fallback:
        config.classic_fallback_policy_label = "off"
        config.classic_fallback_policy = "off"
    if config.classic_fallback_policy == "off":
        config.enable_classic_fallback = False
    config.ablation_no_icfg_modeling = args.ablation_no_icfg_modeling
    config.ablation_no_se_icfg_modeling_strict = args.ablation_no_se_icfg_modeling_strict
    if config.ablation_no_se_icfg_modeling_strict:
        config.ablation_no_icfg_modeling = True
        config.enable_classic_fallback = False
        config.classic_fallback_policy_label = "off"
        config.classic_fallback_policy = "off"
    config.ablation_no_semantic_enhancement = args.ablation_no_semantic_enhancement
    config.ablation_intra_contract_only = args.ablation_intra_contract_only
    config.ablation_no_callback_edges = args.ablation_no_callback_edges
    config.ablation_no_cross_contract_path_recovery = args.ablation_no_cross_contract_path_recovery
    config.ablation_no_state_access_semantics = args.ablation_no_state_access_semantics
    config.ablation_no_state_access_propagation = args.ablation_no_state_access_propagation
    config.ablation_explicit_state_conflict_only = args.ablation_explicit_state_conflict_only
    config.ablation_no_state_conflict = args.ablation_no_state_conflict
    config.ablation_no_lock_context = args.ablation_no_lock_context
    config.ablation_no_path_constraints = args.ablation_no_path_constraints
    config.ablation_no_ror_mismatch_window = args.ablation_no_ror_mismatch_window
    config.ablation_no_ror_propagation = args.ablation_no_ror_propagation
    config.ablation_no_ror_sensitive_sink = args.ablation_no_ror_sensitive_sink

    guardian = ReentrancyGuardian(config)

    try:
        results = guardian.analyze(args.target)
        guardian.generate_reports(
            results,
            args.output,
            write_json=write_json,
            write_csv=write_csv,
        )
        print("\n[OK] Analysis completed successfully!")
    except KeyboardInterrupt:
        print("\n\n[STOP] Analysis interrupted by user")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] Analysis failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
