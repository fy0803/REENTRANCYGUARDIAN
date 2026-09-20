#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import shutil
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reentrancy_guardian"))

from analysis.ccr_detector import CCRDetector
from analysis.path_feasibility import PathFeasibilityChecker
from analysis.ror_detector import RORDetector
from analysis.sink_rules import SinkRuleManager
from analysis.taint_engine import TaintEngine
from config import AnalysisConfig
from fusion.merger import Merger
from fusion.report_filter import PrecisionFilter
from fusion.validator import Validator
from graph.se_icfg_builder import SEICFGBuilder
from models.candidate import CCRCandidate
from main import ReentrancyGuardian, resolve_output_formats, resolve_output_targets
from models.report import VulnerabilityReport
from parser.contract_extractor import ContractExtractor
from parser.normalizer import Normalizer
from parser.slither_loader import SlitherLoader


class SemanticICFGTests(unittest.TestCase):
    def _build_pipeline(self, contract_path: str):
        loader = SlitherLoader()
        slither = loader.load_project(contract_path)
        contracts_info = ContractExtractor(slither).extract_all()
        normalized_nodes = Normalizer().normalize_nodes(contracts_info)

        se_builder = SEICFGBuilder()
        se_builder.build_from_contracts(slither.contracts, contracts_info, normalized_nodes=normalized_nodes)
        return se_builder, se_builder.base_icfg, se_builder.semantic, se_builder.lock, se_builder.mismatch

    def _sample_report(self) -> VulnerabilityReport:
        return VulnerabilityReport(
            vuln_id="TEST-001",
            vuln_type="CCR",
            severity="High",
            source_contract="Pool",
            source_function="withdraw",
            target_contract="Pool",
            target_function="withdraw",
            key_states={"balance", "totalLiquidity"},
            reason="Example finding",
            confidence_score=0.95,
        )

    def _workspace_test_dir(self, name: str) -> Path:
        path = ROOT / ".tmp_test_outputs" / name
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        return path

    def test_delegatecall_targets_are_resolved(self):
        se_builder, builder, _, _, _ = self._build_pipeline(
            str(ROOT / "benchmarks" / "SemanticICFGSample.sol")
        )

        delegate_node = next(
            node
            for node in builder.nodes.values()
            if node.function_key == "DelegateProxy.proxyBump" and node.call_type == "delegatecall"
        )
        target_entry = builder.get_function_entry("LibraryLogic.bump")

        self.assertIn("LibraryLogic.bump", delegate_node.call_targets)
        self.assertIn((delegate_node.node_id, target_entry), builder.edges_call)
        self.assertIn((delegate_node.node_id, target_entry, "delegatecall"), builder.edges_sem)
        self.assertEqual(builder.get_callsite_followup(delegate_node.node_id), delegate_node.node_id + 1)
        self.assertIn(target_entry, builder.get_callsite_callee_entries(delegate_node.node_id))
        for exit_id in builder.get_function_exits("LibraryLogic.bump"):
            self.assertIn((exit_id, delegate_node.node_id + 1), builder.edges_ret)
        self.assertGreaterEqual(se_builder.get_statistics()["inter_contract_callsites"], 1)

    def test_staticcall_targets_are_resolved(self):
        _, builder, _, _, _ = self._build_pipeline(str(ROOT / "benchmarks" / "StaticCallSample.sol"))

        staticcall_node = next(
            node
            for node in builder.nodes.values()
            if node.function_key == "StaticConsumer.refresh" and node.call_type == "staticcall"
        )
        target_entry = builder.get_function_entry("OracleFeed.peek")

        self.assertEqual(staticcall_node.call_target_function, "peek")
        self.assertIn("OracleFeed.peek", staticcall_node.call_targets)
        self.assertIn((staticcall_node.node_id, target_entry), builder.edges_call)
        self.assertEqual(builder.get_callsite_followup(staticcall_node.node_id), staticcall_node.node_id + 1)
        self.assertIn(target_entry, builder.get_callsite_callee_entries(staticcall_node.node_id))
        for exit_id in builder.get_function_exits("OracleFeed.peek"):
            self.assertIn((exit_id, staticcall_node.node_id + 1), builder.edges_ret)

    def test_ror_candidates_keep_graph_reachable_propagation_paths(self):
        _, builder, _, _, mismatch = self._build_pipeline(str(ROOT / "benchmarks" / "SemanticICFGSample.sol"))
        taint = TaintEngine(builder, SinkRuleManager())
        detector = RORDetector(builder, mismatch, taint)

        candidates = detector.detect()
        self.assertTrue(candidates)

        candidate = next(candidate for candidate in candidates if not candidate.external_sink)
        candidate.propagation_path = detector.analyze_propagation(candidate)
        self.assertGreaterEqual(len(candidate.propagation_path), 3)
        self.assertEqual(candidate.propagation_path[0], candidate.start_node_id)
        self.assertIn(candidate.propagation_path[-1], candidate.sink_node_ids)

        for current, nxt in zip(candidate.propagation_path, candidate.propagation_path[1:]):
            self.assertIn(nxt, builder.get_successors(current, include_semantic=True))
        self.assertIn(candidate.propagation_path[0], taint.analysis.node_taint_in)
        self.assertIn(candidate.propagation_path[-1], taint.analysis.node_taint_in)
        self.assertIn("price", taint.analysis.node_taint_in[candidate.propagation_path[-1]])
        self.assertIn("mintAmount", taint.analysis.node_taint_out[candidate.propagation_path[-1]])

    def test_stale_cache_window_can_flow_to_external_readonly_consumer(self):
        _, builder, _, lock, mismatch = self._build_pipeline(str(ROOT / "benchmarks" / "StaleCacheRORSample.sol"))
        taint = TaintEngine(builder, SinkRuleManager())
        detector = RORDetector(builder, mismatch, taint)
        validator = Validator(builder, lock, taint)

        candidates = detector.detect()
        stale_candidates = [
            candidate
            for candidate in candidates
            if candidate.external_sink and "cachedTotalAssets" in candidate.overlap_states
        ]

        self.assertTrue(stale_candidates)
        self.assertTrue(any(validator.validate_ror(candidate)[0] for candidate in stale_candidates))

    def test_quickswap_borrow_transfer_window_reaches_readonly_consumer(self):
        _, builder, _, lock, mismatch = self._build_pipeline(
            str(ROOT / "benchmarks" / "QuickSwapBorrowRORReduced.sol")
        )
        taint = TaintEngine(builder, SinkRuleManager())
        detector = RORDetector(builder, mismatch, taint)
        validator = Validator(builder, lock, taint)

        candidates = detector.detect()
        transfer_candidates = [
            candidate
            for candidate in candidates
            if (
                candidate.external_sink
                and candidate.window_function == "doTransferOut"
                and candidate.query_function == "QuickSwapBorrowRORReduced.exchangeRateStored"
                and "cash" in candidate.overlap_states
            )
        ]

        self.assertTrue(transfer_candidates)
        self.assertTrue(any(validator.validate_ror(candidate)[0] for candidate in transfer_candidates))

    def test_balanced_flow_is_not_reported_as_reentrancy(self):
        _, builder, semantic, lock, mismatch = self._build_pipeline(str(ROOT / "benchmarks" / "BalancedSample.sol"))
        ccr_detector = CCRDetector(builder, semantic, lock)
        taint = TaintEngine(builder, SinkRuleManager())
        ror_detector = RORDetector(builder, mismatch, taint)
        validator = Validator(builder, lock, taint)

        ccr_candidates = ccr_detector.detect()
        ror_candidates = ror_detector.detect()

        self.assertFalse(ccr_candidates)
        self.assertFalse(ror_candidates)
        self.assertFalse(mismatch.mismatch_windows)
        self.assertFalse(any(validator.validate_ccr(candidate)[0] for candidate in ccr_candidates))
        self.assertFalse(any(validator.validate_ror(candidate)[0] for candidate in ror_candidates))

    def test_classic_call_before_effect_pattern_is_reported_as_ccr(self):
        _, builder, semantic, lock, mismatch = self._build_pipeline(
            str(
                ROOT
                / "contracts"
                / "smartbugs"
                / "0x4e73b32ed6c35f570686b89848e5f39f20ecc106"
                / "0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol"
            )
        )
        ccr_detector = CCRDetector(builder, semantic, lock)
        taint = TaintEngine(builder, SinkRuleManager())
        validator = Validator(builder, lock, taint)

        ccr_candidates = ccr_detector.detect()
        valid_candidates = [candidate for candidate in ccr_candidates if validator.validate_ccr(candidate)[0]]

        self.assertFalse(mismatch.mismatch_windows)
        self.assertTrue(ccr_candidates)
        self.assertTrue(valid_candidates)
        self.assertTrue(any("balances" in candidate.overlap_states for candidate in valid_candidates))
        self.assertTrue(any(candidate.callback_entry_function == "Collect" for candidate in valid_candidates))
        self.assertTrue(any("Classic Reentrancy detected" in candidate.reason for candidate in valid_candidates))

        guardian = ReentrancyGuardian(AnalysisConfig())
        report = guardian._to_ccr_report(valid_candidates[0], 0.8, "High")
        self.assertEqual(report.vuln_type, "Classic Reentrancy")
        self.assertEqual(report.vuln_family, "CCR")

    def test_cross_contract_ccr_is_labeled_separately(self):
        candidate = CCRCandidate(
            candidate_id="ccr_cross",
            source_contract="Pool",
            entry_function="withdraw",
            external_call_node=10,
            target_contract="Vault",
            callback_entry_function="deposit",
            callback_kind="cross_contract",
            overlap_states={"balances"},
            path_node_ids=[10, 20],
        )
        guardian = ReentrancyGuardian(AnalysisConfig())
        report = guardian._to_ccr_report(candidate, 0.8, "High")
        self.assertEqual(report.vuln_type, "Cross-Contract Reentrancy")
        self.assertEqual(report.vuln_family, "CCR")

    def test_resolved_cross_contract_callback_is_labeled_separately(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "benchmarks" / "CrossContractLabelSample.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]

        self.assertTrue(valid_candidates)
        self.assertTrue(
            any(
                candidate.entry_function == "withdraw"
                and candidate.callback_entry_function == "forward"
                and candidate.callback_kind == "cross_contract"
                and candidate.classification_label() == "Cross-Contract Reentrancy"
                for candidate in valid_candidates
            )
        )

    def test_precise_cross_contract_callbacks_do_not_drop_classic_fallbacks(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "benchmarks" / "CrossContractLabelSample.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]

        self.assertTrue(
            any(
                candidate.entry_function == "withdraw"
                and candidate.callback_entry_function == "forward"
                and candidate.callback_kind == "cross_contract"
                for candidate in valid_candidates
            )
        )
        self.assertTrue(
            any(
                candidate.entry_function == "withdraw"
                and candidate.callback_entry_function == "deposit"
                and candidate.callback_kind == "classic"
                and candidate.classification_label() == "Classic Reentrancy"
                for candidate in valid_candidates
            )
        )

    def test_detector_can_disable_classic_fallback_callbacks(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "benchmarks" / "CrossContractLabelSample.sol")
        )
        detector = CCRDetector(builder, semantic, lock, enable_classic_fallback=False)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]

        self.assertTrue(valid_candidates)
        self.assertTrue(any(candidate.callback_kind == "cross_contract" for candidate in valid_candidates))
        self.assertFalse(any(candidate.callback_kind == "classic" for candidate in valid_candidates))

    def test_strict_classic_fallback_prunes_protocol_cross_entry_callbacks(self):
        call_node = SimpleNamespace(
            call_type="high_level_call",
            expression="token.transfer(receiver, amount)",
            function_name="setRouter",
            call_target_contract="IERC20",
            call_target_function="transfer",
        )
        strict_detector = CCRDetector(None, None, None, classic_fallback_policy="strict_v6")
        normal_detector = CCRDetector(None, None, None, classic_fallback_policy="normal")

        self.assertFalse(
            strict_detector._allow_classic_fallback_entry(call_node, "Vault.withdraw")
        )
        self.assertTrue(
            strict_detector._allow_classic_fallback_entry(call_node, "Vault.setRouter")
        )
        self.assertTrue(
            normal_detector._allow_classic_fallback_entry(call_node, "Vault.withdraw")
        )

        user_call_node = SimpleNamespace(
            call_type="high_level_call",
            expression="token.transfer(receiver, amount)",
            function_name="transfer",
            call_target_contract="IERC20",
            call_target_function="transfer",
        )
        self.assertTrue(
            strict_detector._allow_classic_fallback_entry(user_call_node, "Vault.withdraw")
        )

        low_level_call = SimpleNamespace(
            call_type="call",
            expression="msg.sender.call{value: amount}(\"\")",
            function_name="settle",
            call_target_contract=None,
            call_target_function=None,
        )
        self.assertTrue(
            strict_detector._allow_classic_fallback_entry(low_level_call, "Vault.withdraw")
        )

        helper_call = SimpleNamespace(
            call_type="high_level_call",
            expression="synthetix.issueSynths(mintAmount)",
            function_name="_stake",
            call_target_contract="Synthetix",
            call_target_function="issueSynths",
        )
        self.assertFalse(
            strict_detector._allow_classic_fallback_entry(
                helper_call,
                "Vault.claim",
                entry_func="Vault.renounceOwnership",
            )
        )
        claim_call = SimpleNamespace(
            call_type="call",
            expression="_msgSender().call{value: rewardsSent}()",
            function_name="claim",
            call_target_contract=None,
            call_target_function=None,
        )
        self.assertFalse(
            strict_detector._allow_classic_fallback_entry(
                claim_call,
                "Vault.claim",
                entry_func="Vault.renounceOwnership",
            )
        )
        self.assertTrue(
            strict_detector._allow_classic_fallback_entry(
                helper_call,
                "Vault.claim",
                entry_func="Vault.claim",
            )
        )

        token_transfer_call = SimpleNamespace(
            call_type="call",
            expression="_msgSender().call{value: rewardsSent}()",
            function_name="transfer",
            call_target_contract=None,
            call_target_function=None,
        )
        reward_states = {"_rewardsLastClaim", "ethRewardsBalance"}
        self.assertFalse(
            strict_detector._allow_classic_fallback_entry(
                token_transfer_call,
                "Vault.claimETHRewards",
                entry_func="Vault.transfer",
                relevant_states=reward_states,
            )
        )
        self.assertTrue(
            strict_detector._allow_classic_fallback_entry(
                claim_call,
                "Vault.claimETHRewards",
                entry_func="Vault.claimETHRewards",
                relevant_states=reward_states,
            )
        )

        strict_detector.icfg = SimpleNamespace(
            function_meta={
                "Vault.rebalance": {"modifiers": ["onlyOwnerOrManager"]},
                "Vault.claim": {"modifiers": []},
            }
        )
        self.assertFalse(
            strict_detector._allow_classic_fallback_entry(
                helper_call,
                "Vault.claim",
                entry_func="Vault.rebalance",
            )
        )

    def test_balance_dependent_reentrancy_is_detected_as_classic(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "benchmarks" / "BalanceDependentReentrancySample.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]

        self.assertTrue(valid_candidates)
        self.assertTrue(
            any(
                candidate.entry_function == "sendCall"
                and candidate.callback_entry_function == "sendCall"
                and "contract_balance" in candidate.overlap_states
                and candidate.classification_label() == "Classic Reentrancy"
                for candidate in valid_candidates
            )
        )

    def test_modifier_based_reentrancy_is_detected(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "contracts" / "smartbugs" / "modifier_reentrancy" / "modifier_reentrancy.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        self.assertTrue(candidates)

        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]
        self.assertTrue(valid_candidates)
        self.assertTrue(any(candidate.entry_function == "airDrop" for candidate in valid_candidates))
        self.assertTrue(any(candidate.callback_entry_function == "airDrop" for candidate in valid_candidates))
        self.assertTrue(any("tokenBalance" in candidate.overlap_states for candidate in valid_candidates))

    def test_loader_retries_with_compat_copy_for_legacy_low_level_call(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "contracts" / "smartbugs" / "reentrancy_insecure" / "reentrancy_insecure.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        self.assertTrue(candidates)
        self.assertTrue(any(validator.validate_ccr(candidate)[0] for candidate in candidates))

    def test_loader_prefers_same_minor_patch_when_exact_patch_is_missing(self):
        root = self._workspace_test_dir("exact_patch_fallback")
        contract = root / "ExactPatch.sol"
        contract.write_text("pragma solidity 0.5.11;\ncontract ExactPatch {}\n", encoding="utf-8")

        loader = SlitherLoader()
        with patch.object(SlitherLoader, "_installed_solc_versions", return_value=["0.4.25", "0.5.10", "0.5.16"]):
            with patch("parser.slither_loader.current_version", return_value=("0.4.25", "mock")):
                self.assertEqual(loader._resolve_solc_version(str(contract)), "0.5.16")

    def test_loader_supports_compound_range_pragmas(self):
        root = self._workspace_test_dir("compound_range")
        contract = root / "CompoundRange.sol"
        contract.write_text("pragma solidity >=0.6.0 <0.8.0;\ncontract CompoundRange {}\n", encoding="utf-8")

        loader = SlitherLoader()
        with patch.object(SlitherLoader, "_installed_solc_versions", return_value=["0.4.25", "0.5.17", "0.6.12", "0.8.20"]):
            with patch("parser.slither_loader.current_version", return_value=("0.4.25", "mock")):
                self.assertEqual(loader._resolve_solc_version(str(contract)), "0.6.12")

    def test_loader_discovers_matching_versions_from_additional_artifact_roots(self):
        root = self._workspace_test_dir("artifact_root_discovery")
        contract = root / "RangeContract.sol"
        contract.write_text("pragma solidity >=0.6.0 <0.8.0;\ncontract RangeContract {}\n", encoding="utf-8")

        extra_root = root / "artifacts"
        extra_artifact = extra_root / "solc-0.7.0"
        extra_artifact.mkdir(parents=True, exist_ok=True)
        (extra_artifact / "solc-0.7.0").write_text("", encoding="utf-8")

        loader = SlitherLoader()
        with patch("parser.slither_loader.installed_versions", return_value=["0.6.12"]):
            with patch("parser.slither_loader.current_version", return_value=("0.6.12", "mock")):
                with patch.object(SlitherLoader, "_artifact_roots", return_value=[extra_root]):
                    self.assertEqual(loader._resolve_solc_version(str(contract)), "0.7.0")

    def test_loader_relaxes_exact_pragma_in_compat_copy_when_patch_is_missing(self):
        root = self._workspace_test_dir("relaxed_exact_pragma")
        contract = root / "RelaxPragma.sol"
        contract.write_text("pragma solidity 0.5.11;\ncontract RelaxPragma {}\n", encoding="utf-8")

        loader = SlitherLoader()
        with patch.object(SlitherLoader, "_installed_solc_versions", return_value=["0.4.25", "0.5.16", "0.5.17"]):
            compat_path = loader._write_compat_file(str(contract))

        self.assertIsNotNone(compat_path)
        compat_text = Path(compat_path).read_text(encoding="utf-8")
        self.assertIn("pragma solidity >=0.5.11 <0.6.0;", compat_text)

    def test_loader_normalizes_invalid_spdx_in_compat_copy(self):
        root = self._workspace_test_dir("invalid_spdx")
        contract = root / "InvalidSpdx.sol"
        contract.write_text(
            "/*\nSPDX-License-Identifier: M虊叹蛻虝探蛯蜆蛢虖虆蛯蜄\n*/\npragma solidity ^0.8.6;\ncontract InvalidSpdx {}\n",
            encoding="utf-8",
        )

        loader = SlitherLoader()
        compat_path = loader._write_compat_file(str(contract))

        self.assertIsNotNone(compat_path)
        compat_text = Path(compat_path).read_text(encoding="utf-8")
        self.assertIn("SPDX-License-Identifier: UNLICENSED", compat_text)
        self.assertIn("pragma solidity ^0.8.6;", compat_text)

    def test_loader_rewrites_legacy_invalid_jump_label_assembly(self):
        source = """pragma solidity 0.4.9;
contract LegacyCreate {
  function create(uint _value, bytes _code) internal returns (address o_addr) {
    assembly {
      o_addr := create(_value, add(_code, 0x20), mload(_code))
      jumpi(invalidJumpLabel, iszero(extcodesize(o_addr)))
    }
  }
}
"""
        rewritten = SlitherLoader()._rewrite_compat_content(source)

        self.assertNotIn("invalidJumpLabel", rewritten)
        self.assertIn("o_addr := create(_value, add(_code, 0x20), mload(_code))", rewritten)
        self.assertIn("if (o_addr == 0)", rewritten)
        self.assertIn("throw;", rewritten)

    def test_low_level_call_to_contract_typed_state_var_resolves_fallback_target(self):
        _, builder, _, _, _ = self._build_pipeline(str(ROOT / "contracts" / "ccr.sol"))

        low_level_node = next(
            node
            for node in builder.nodes.values()
            if node.function_key == "Etherhero.makeDeposit"
            and node.call_type == "call"
            and "stubF.call.value" in node.expression
        )
        target_entry = builder.get_function_entry("EtherheroStabilizationFund.fallback")

        self.assertEqual(low_level_node.call_target_contract, "EtherheroStabilizationFund")
        self.assertEqual(low_level_node.call_target_function, "fallback")
        self.assertIn("EtherheroStabilizationFund.fallback", low_level_node.call_targets)
        self.assertIn(target_entry, builder.get_callsite_callee_entries(low_level_node.node_id))

    def test_low_level_call_to_constructor_sender_var_resolves_creator_fallback(self):
        _, builder, _, _, _ = self._build_pipeline(str(ROOT / "contracts" / "ccr.sol"))

        low_level_node = next(
            node
            for node in builder.nodes.values()
            if node.function_key == "EtherheroStabilizationFund.ReturnEthToEtherhero"
            and node.call_type == "call"
            and "etherHero.call.value" in node.expression
        )
        target_entry = builder.get_function_entry("Etherhero.fallback")

        self.assertEqual(low_level_node.call_target_contract, "Etherhero")
        self.assertEqual(low_level_node.call_target_function, "fallback")
        self.assertIn("Etherhero.fallback", low_level_node.call_targets)
        self.assertIn(target_entry, builder.get_callsite_callee_entries(low_level_node.node_id))

    def test_interprocedural_classic_reentrancy_bonus_is_detected(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(ROOT / "contracts" / "smartbugs" / "reentrancy_bonus" / "reentrancy_bonus.sol")
        )
        detector = CCRDetector(builder, semantic, lock)
        validator = Validator(builder, lock, None)

        candidates = detector.detect()
        valid_candidates = [candidate for candidate in candidates if validator.validate_ccr(candidate)[0]]

        self.assertTrue(valid_candidates)
        self.assertTrue(
            any(
                candidate.entry_function == "getFirstWithdrawalBonus"
                and candidate.callback_entry_function == "getFirstWithdrawalBonus"
                and "claimedBonus" in candidate.overlap_states
                for candidate in valid_candidates
            )
        )

    def test_internal_call_inside_require_keeps_post_call_state_window(self):
        _, builder, semantic, lock, _ = self._build_pipeline(
            str(
                ROOT
                / "contracts"
                / "reentrant_contracts"
                / "0x79ad73567e7f9a5b4a2d28264f78aff9d971cf14.sol"
            )
        )
        detector = CCRDetector(builder, semantic, lock)

        send_entry = builder.get_function_entry("_50Win.send")
        require_send_nodes = [
            node
            for node in builder.nodes.values()
            if node.function_key == "_50Win.takeBet" and "send(" in node.expression
        ]

        self.assertEqual(len(require_send_nodes), 2)
        for node in require_send_nodes:
            self.assertIn("_50Win.send", node.call_targets)
            self.assertIn((node.node_id, send_entry), builder.edges_call)
            self.assertIn((23, 62), builder.edges_ret)
            self.assertIn((25, 62), builder.edges_ret)

        candidates = detector.detect()
        self.assertTrue(candidates)
        self.assertTrue(
            any(
                candidate.entry_function == "takeBet"
                and candidate.callback_entry_function in {"takeBet", "cancelBet", "createBet"}
                and "Bets" in candidate.overlap_states
                for candidate in candidates
            )
        )

    def test_z3_path_feasibility_distinguishes_sat_and_unsat_paths(self):
        _, builder, _, lock, _ = self._build_pipeline(str(ROOT / "benchmarks" / "ConstraintSample.sol"))
        validator = Validator(builder, lock, None)

        possible_path = builder.get_function_nodes("ConstraintProbe.possible")
        impossible_path = builder.get_function_nodes("ConstraintProbe.impossible")

        self.assertTrue(validator.path_solver.available)
        self.assertTrue(validator.path_solver.is_path_feasible(possible_path))
        self.assertFalse(validator.path_solver.is_path_feasible(impossible_path))

    def test_joint_taint_and_z3_validation_filters_unsat_ror(self):
        _, builder, _, lock, mismatch = self._build_pipeline(str(ROOT / "benchmarks" / "UnsatRORSample.sol"))
        taint = TaintEngine(builder, SinkRuleManager())
        detector = RORDetector(builder, mismatch, taint)
        validator = Validator(builder, lock, taint)

        candidates = detector.detect()
        self.assertTrue(candidates)

        candidate = candidates[0]
        self.assertTrue(candidate.tainted_query_vars)
        self.assertTrue(candidate.tainted_sink_vars)

        is_valid, reason = validator.validate_ror(candidate)
        self.assertFalse(is_valid)
        self.assertEqual(reason, "Propagation path constraints are unsatisfiable")
        self.assertIn("price", candidate.tainted_constraint_vars)

    def test_path_feasibility_skips_unsupported_call_constraints_with_reduced_precision(self):
        fake_icfg = SimpleNamespace(
            nodes={
                1: SimpleNamespace(expression="require(checkBalance(msg.sender))"),
            }
        )
        checker = PathFeasibilityChecker(fake_icfg)

        self.assertTrue(checker.available)

        result = checker.analyze_path([1])

        self.assertTrue(result.feasible)
        self.assertTrue(result.reduced_precision)
        self.assertIn(1, result.skipped_constraints_by_node)
        self.assertIn("Unsupported AST node", result.skipped_constraints_by_node[1])

    def test_output_formats_default_to_json_only(self):
        self.assertEqual(resolve_output_formats(False, False), (True, False))
        self.assertEqual(resolve_output_formats(True, False), (True, False))
        self.assertEqual(resolve_output_formats(False, True), (False, True))
        self.assertEqual(resolve_output_formats(True, True), (True, True))

    def test_normalized_nodes_are_applied_to_icfg_nodes(self):
        loader = SlitherLoader()
        slither = loader.load_project(str(ROOT / "benchmarks" / "SemanticICFGSample.sol"))
        contracts_info = ContractExtractor(slither).extract_all()
        normalized_nodes = Normalizer().normalize_nodes(contracts_info)

        chosen = next(
            node
            for node in normalized_nodes.values()
            if node.function_key == "SamplePool.unstake" and node.writes
        )
        chosen.writes.add("normalized_total_staked")

        se_builder = SEICFGBuilder()
        se_builder.build_from_contracts(slither.contracts, contracts_info, normalized_nodes=normalized_nodes)

        matching_node = next(
            node
            for node in se_builder.base_icfg.nodes.values()
            if node.function_key == "SamplePool.unstake"
            and node.source_node_id == chosen.source_node_id
        )
        self.assertIn("normalized_total_staked", matching_node.writes)

    def test_merger_combines_near_duplicate_reports(self):
        merger = Merger()
        report_a = VulnerabilityReport(
            vuln_id="CCR-A",
            vuln_type="CCR",
            severity="High",
            source_contract="Pool",
            source_function="withdraw",
            target_contract="Pool",
            target_function="withdraw",
            key_states={"balances", "totalLiquidity"},
            overlap_states={"balances", "totalLiquidity"},
            external_call={"node_id": 10},
            callback_entry={"function": "withdraw"},
            evidence_path=[{"node_id": 10}, {"node_id": 20}],
            confidence_score=0.92,
        )
        report_b = VulnerabilityReport(
            vuln_id="CCR-B",
            vuln_type="CCR",
            severity="Medium",
            source_contract="Pool",
            source_function="withdraw",
            target_contract="Pool",
            target_function="withdraw",
            key_states={"balances"},
            overlap_states={"balances"},
            external_call={"node_id": 11},
            callback_entry={"function": "withdraw"},
            evidence_path=[{"node_id": 11}, {"node_id": 20}],
            confidence_score=0.61,
        )

        merged = merger.merge_duplicate_vulnerabilities([report_a, report_b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].key_states, {"balances", "totalLiquidity"})

    def test_precision_filter_keeps_eth_valued_reentrancy_reports(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ETH",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Bank",
            source_function="withdraw",
            target_contract="Bank",
            target_function="withdraw",
            key_states={"balances"},
            external_call={"expression": "msg.sender.call.value(balances[msg.sender])()"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_precision_filter_drops_token_bookkeeping_without_eth_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-TOKEN",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Token",
            source_function="transfer",
            target_contract="Token",
            target_function="transferFrom",
            key_states={"balances", "totalSupply_"},
            external_call={"expression": "balances[msg.sender] = balances[msg.sender].sub(value)"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertEqual(dropped[0][0], report)
        self.assertIn("token bookkeeping", dropped[0][1])

    def test_precision_filter_drops_ror_notification_external_consumer(self):
        report = VulnerabilityReport(
            vuln_id="ROR-NOTIFY",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="RateProvider",
            source_function="updateRate",
            key_states={"committedRate"},
            mismatch_window={"window_id": "pre_external_window_RateProvider.updateRate_7"},
            query_function="RateProvider.getRate",
            sink_function="__external_readonly_consumer__",
            evidence_path=[
                {
                    "expression": "hook.afterRateCommit(committedVersion)",
                }
            ],
            confidence_score=0.73,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("notification/refresh hook", dropped[0][1])

    def test_precision_filter_keeps_core_ror_external_consumer(self):
        report = VulnerabilityReport(
            vuln_id="ROR-CONIC",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="ConicEthPool",
            source_function="depositFor",
            key_states={"_cachedTotalUnderlying"},
            mismatch_window={"window_id": "stale_window_ConicEthPool.depositFor_107"},
            query_function="ConicEthPool.cachedTotalUnderlying",
            sink_function="__external_readonly_consumer__",
            evidence_path=[
                {
                    "expression": "underlying.safeTransferFrom(msg.sender,address(this),underlyingAmount)",
                }
            ],
            confidence_score=0.79,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_precision_filter_drops_pure_library_computation(self):
        report = VulnerabilityReport(
            vuln_id="CCR-PURE",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Game",
            source_function="buy",
            target_contract="Game",
            target_function="withdraw",
            key_states={"round_"},
            external_call={"expression": "seed = uint256(keccak256(abi.encodePacked(block.timestamp)))"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("pure/library", dropped[0][1])

    def test_precision_filter_keeps_external_call_wrapped_by_pure_terms(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MODIFIER",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="ModifierEntrancy",
            source_function="airDrop",
            target_contract="ModifierEntrancy",
            target_function="airDrop",
            key_states={"tokenBalance"},
            external_call={
                "expression": (
                    "require(bool)(keccak256()(abi.encodePacked(Nu Token)) == "
                    "Bank(msg.sender).supportsToken())"
                )
            },
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_precision_filter_drops_readonly_query_call(self):
        report = VulnerabilityReport(
            vuln_id="CCR-QUERY",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Crowdsale",
            source_function="buy",
            target_contract="Crowdsale",
            target_function="finalize",
            key_states={"weiRaised", "tokensSold"},
            external_call={
                "expression": "tokenAmount = pricingStrategy.calculatePrice(weiAmount, weiRaised)"
            },
            confidence_score=0.72,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("read-only query", dropped[0][1])

    def test_precision_filter_drops_readonly_query_with_accounting_variable_names(self):
        report = VulnerabilityReport(
            vuln_id="CCR-BALANCEOF",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Exchange",
            source_function="settle",
            target_contract="Exchange",
            target_function="settle",
            key_states={"orders"},
            external_call={
                "expression": "fee = feeDeposit * token.balanceOf(user) / token.totalSupply()"
            },
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("read-only query", dropped[0][1])

    def test_precision_filter_drops_protocol_queue_bookkeeping(self):
        report = VulnerabilityReport(
            vuln_id="CCR-PLASMA-QUEUE",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="ExitGameController",
            source_function="enqueue",
            target_contract="PlasmaFramework",
            target_function="enqueue",
            key_states={"delegations"},
            external_call={"expression": "queue.insert(priority)"},
            callback_entry={"function": "enqueue", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("priority queue", dropped[0][1])

    def test_precision_filter_drops_uniswap_v3_guarded_ror(self):
        report = VulnerabilityReport(
            vuln_id="ROR-UNISWAP-V3",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="UniswapV3Pool",
            source_function="swap",
            key_states={"slot0", "liquidity"},
            mismatch_window={"window_id": "stale_window_UniswapV3Pool.swap_1027"},
            query_function="UniswapV3Pool.observe",
            sink_function="__external_readonly_consumer__",
            evidence_path=[{"expression": "liquidityNet = ticks.cross(step.tickNext, fee0, fee1)"}],
            confidence_score=0.78,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("Uniswap V3", dropped[0][1])

    def test_precision_filter_keeps_pancake_factory_all_pairs_ror(self):
        report = VulnerabilityReport(
            vuln_id="ROR-PANCAKE-FACTORY",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="PancakeFactory",
            source_function="createPair",
            key_states={"allPairs"},
            mismatch_window={"window_id": "stale_window_PancakeFactory.createPair_10"},
            query_function="PancakeFactory.allPairsLength",
            sink_function="__external_readonly_consumer__",
            evidence_path=[{"expression": "allPairs.push(pair)"}],
            confidence_score=0.73,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_precision_filter_drops_uniswap_v3_guarded_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-UNISWAP-V3",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="UniswapV3Pool",
            source_function="mint",
            target_contract="UniswapV3Pool",
            target_function="burn",
            key_states={"slot0"},
            external_call={
                "expression": "IUniswapV3MintCallback(msg.sender).uniswapV3MintCallback(amount0, amount1, data)"
            },
            callback_entry={"function": "burn", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("Uniswap V3", dropped[0][1])

    def test_precision_filter_drops_trusted_protocol_getter_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-NODE-REGISTRY",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="NodeRegistry",
            source_function="revealConvict",
            target_contract="NodeRegistry",
            target_function="updateNode",
            key_states={"nodes", "signerIndex", "urlIndex"},
            external_call={"expression": "evmBlockhash = blockRegistry.blockhashMapping(_blockNumber)"},
            callback_entry={"function": "updateNode", "kind": "classic"},
            confidence_score=0.69,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_trusted_protocol_accounting_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-STABILITY-POOL",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="StabilityPool",
            source_function="provideToSP",
            target_contract="StabilityPool",
            target_function="offset",
            key_states={"totalLUSDDeposits"},
            external_call={"expression": "LQTYIssuance = communityIssuance.issueLQTY()"},
            callback_entry={"function": "offset", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_stability_pool_protocol_accounting_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-STABILITY-POOL-ACTIVE",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="StabilityPool",
            source_function="offset",
            target_contract="StabilityPool",
            target_function="provideToSP",
            key_states={"totalLUSDDeposits"},
            external_call={"expression": "activePool.decreaseLUSDDebt(_debtToOffset)"},
            callback_entry={"function": "provideToSP", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_stability_pool_deposit_protocol_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-STABILITY-POOL-DEPOSITS",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="StabilityPool",
            source_function="withdrawFromSP",
            target_contract="StabilityPool",
            target_function="provideToSP",
            key_states={"deposits"},
            external_call={"expression": "lusdToken.returnFromPool(address(this), _depositor, LUSDWithdrawal)"},
            callback_entry={"function": "provideToSP", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_protocol_view_staking_ror(self):
        report = VulnerabilityReport(
            vuln_id="ROR-STAKING-VIEW",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="Staking",
            source_function="_stake",
            key_states={"stakes"},
            mismatch_window={"window_id": "stale_window_Staking._stake_336"},
            query_function="Staking.balanceOf",
            sink_function="__external_readonly_consumer__",
            evidence_path=[{"expression": "token.safeTransferFrom(msg.sender,address(this),amount)"}],
            confidence_score=0.73,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("protocol view", dropped[0][1])

    def test_precision_filter_drops_stability_pool_total_lusd_ror(self):
        report = VulnerabilityReport(
            vuln_id="ROR-STABILITY-POOL-VIEW",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="StabilityPool",
            source_function="_sendLUSDtoStabilityPool",
            key_states={"totalLUSDDeposits"},
            mismatch_window={"window_id": "stale_window_StabilityPool._sendLUSDtoStabilityPool_1968"},
            query_function="StabilityPool.getTotalLUSDDeposits",
            sink_function="__external_readonly_consumer__",
            evidence_path=[{"expression": "lusdToken.sendToPool(_address,address(this),_amount)"}],
            confidence_score=0.73,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("protocol view", dropped[0][1])

    def test_precision_filter_drops_holdefi_settings_ror(self):
        report = VulnerabilityReport(
            vuln_id="ROR-HOLDEFI-SETTINGS",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="High",
            source_contract="HoldefiSettings",
            source_function="removeMarket",
            key_states={"marketsList"},
            mismatch_window={"window_id": "stale_window_HoldefiSettings.removeMarket_178"},
            query_function="HoldefiSettings.getMarketsList",
            sink_function="__external_readonly_consumer__",
            evidence_path=[{"expression": "holdefiContract.beforeChangeBorrowRate(market)"}],
            confidence_score=0.75,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("protocol view", dropped[0][1])

    def test_precision_filter_drops_holdefi_settings_config_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-HOLDEFI-SETTINGS",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="HoldefiSettings",
            source_function="setBorrowRate",
            target_contract="HoldefiSettings",
            target_function="setBorrowRate",
            key_states={"marketAssets"},
            external_call={"expression": "holdefiContract.beforeChangeBorrowRate(market)"},
            callback_entry={"function": "setBorrowRate", "kind": "classic"},
            confidence_score=0.75,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_sigmoid_role_parameter_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-SIGMOID-PARAMS",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="SigmoidCuratorVault",
            source_function="buyCuratorTokens",
            target_contract="SigmoidCuratorVault",
            target_function="buyCuratorTokens",
            key_states={"curatorTokenSupply", "reserves"},
            external_call={"expression": "(a,b,c) = addressManager.parameterManager().bondingCurveParams()"},
            callback_entry={"function": "buyCuratorTokens", "kind": "classic"},
            confidence_score=0.75,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("trusted protocol", dropped[0][1])

    def test_precision_filter_drops_dex_config_even_with_value_call(self):
        report = VulnerabilityReport(
            vuln_id="CCR-DEX-CONFIG",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="addLiquidity",
            target_contract="Token",
            target_function="addLiquidity",
            key_states={"uniswapV2Router", "uniswapV2Pair"},
            external_call={
                "expression": "uniswapV2Router.addLiquidityETH{value: address(this).balance}(address(this), amount, 0, 0, owner(), block.timestamp)"
            },
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("DEX configuration", dropped[0][1])

    def test_precision_filter_drops_token_transfer_without_eth_value(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ERC20-TRANSFER",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Lock",
            source_function="release",
            target_contract="Lock",
            target_function="release",
            key_states={"isReleased"},
            external_call={"expression": "token_reward.transfer(beneficiary, tokenAmount)"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("token transfer", dropped[0][1])

    def test_precision_filter_keeps_channel_token_transfer_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-SPANK-LC-TIMEOUT",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="LedgerChannel",
            source_function="LCOpenTimeout",
            target_contract="LedgerChannel",
            target_function="LCOpenTimeout",
            key_states={"Channels"},
            external_call={
                "expression": (
                    "require(bool,string)(Channels[_lcID].token.transfer("
                    "Channels[_lcID].partyAddresses[0],Channels[_lcID].erc20Balances[0]),"
                    "CreateChannel: token transfer failure)"
                )
            },
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_precision_filter_drops_token_approval_classic_fallback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-APPROVE-MAINTENANCE",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="setRouter",
            target_contract="Token",
            target_function="setMaxWalletAmount",
            key_states={"_maxWalletAmount"},
            external_call={
                "expression": (
                    "IERC20(uniswapV2Pair).approve(address(uniswapV2Router), "
                    "type(uint256).max)"
                )
            },
            callback_entry={"function": "setMaxWalletAmount", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("token approval", dropped[0][1])

    def test_precision_filter_keeps_classic_eth_value_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ETH-VALUE-CLASSIC",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Bank",
            source_function="withdraw",
            target_contract="Bank",
            target_function="withdraw",
            key_states={"balances"},
            external_call={"expression": "msg.sender.call{value: amount}()"},
            callback_entry={"function": "withdraw", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_strict_classic_policy_drops_fixed_admin_receiver_fallback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MARKETING-WALLET",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="swapBack",
            target_contract="Token",
            target_function="transfer",
            key_states={"contract_balance"},
            external_call={
                "expression": "address(marketingWallet).call{value: marketingPayout}()"
            },
            callback_entry={"function": "transfer", "kind": "classic"},
            confidence_score=0.67,
        )

        normal_kept, normal_dropped = PrecisionFilter().filter_reports([report])
        strict_kept, strict_dropped = PrecisionFilter(
            classic_fallback_policy="strict"
        ).filter_reports([report])
        strict_v6_kept, strict_v6_dropped = PrecisionFilter(
            classic_fallback_policy="strict_v6"
        ).filter_reports([report])

        self.assertEqual(normal_kept, [report])
        self.assertFalse(normal_dropped)
        self.assertFalse(strict_kept)
        self.assertIn("strict classic fallback", strict_dropped[0][1])
        self.assertFalse(strict_v6_kept)
        self.assertIn("strict classic fallback", strict_v6_dropped[0][1])

    def test_strict_classic_policy_keeps_msg_sender_value_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-USER-WITHDRAW",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Bank",
            source_function="withdraw",
            target_contract="Bank",
            target_function="withdraw",
            key_states={"balances"},
            external_call={"expression": "msg.sender.call{value: amount}()"},
            callback_entry={"function": "withdraw", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_strict_classic_policy_drops_recovery_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-WITHDRAW-STUCK-ETH",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="withdrawStuckETH",
            target_contract="Token",
            target_function="withdrawStuckETH",
            key_states={"contract_balance"},
            external_call={"expression": "address(msg.sender).call{value: address(this).balance}()"},
            callback_entry={"function": "withdrawStuckETH", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_token_sale_fallback_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-TOKEN-SALE-FALLBACK",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Sale",
            source_function="fallback",
            target_contract="Sale",
            target_function="fallback",
            key_states={"soldTokensCounter"},
            external_call={"expression": "tokenReward.transfer(msg.sender, sendTokens)"},
            callback_entry={"function": "fallback", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_fixed_recipient_token_lifecycle_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-END-SALE-ADMIN-TRANSFER",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Sale",
            source_function="endSale",
            target_contract="Sale",
            target_function="endSale",
            key_states={"contract_balance"},
            external_call={"expression": "tokenContract.transfer(admin, tokenContract.balanceOf(this))"},
            callback_entry={"function": "endSale", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_authorization_config_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-AUTH-CONFIG",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="BountyProgram",
            source_function="setBountyWalletAddress",
            target_contract="BountyProgram",
            target_function="setBountyWalletAddress",
            key_states={"bountyAddress"},
            external_call={"expression": "require(contractManager.authorize(contractName, msg.sender))"},
            callback_entry={"function": "setBountyWalletAddress", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_fixed_recipient_reward_transfer(self):
        report = VulnerabilityReport(
            vuln_id="CCR-COLLECT-BACK",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Airdrop",
            source_function="collectBack",
            target_contract="Airdrop",
            target_function="collectBack",
            key_states={"totalCandyNo"},
            external_call={"expression": "tokenReward.transfer(collectorAddress, totalCandyNo * 1e18)"},
            callback_entry={"function": "collectBack", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_fixed_fee_collector_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-FEE-COLLECTOR",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Bank",
            source_function="withdraw",
            target_contract="Bank",
            target_function="withdraw",
            key_states={"balance"},
            external_call={"expression": "feeCollector.call.value(fee)()"},
            callback_entry={"function": "withdraw", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_dai_deposit_transfer_self_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-DAI-DEPOSIT",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Vault",
            source_function="depositDai",
            target_contract="Vault",
            target_function="depositDai",
            key_states={"deposits"},
            external_call={"expression": "DaiContract.transferFrom(msg.sender, address(this), _amount)"},
            callback_entry={"function": "depositDai", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_untainted_receiver_bookkeeping_callbacks(self):
        reports = [
            VulnerabilityReport(
                vuln_id="CCR-STATUS-INBOUND",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Dao",
                source_function="submitProposal",
                target_contract="Dao",
                target_function="processProposal",
                key_states={"_status"},
                external_call={
                    "expression": "IERC20(tributeToken).safeTransferFrom(msg.sender, address(this), amount)"
                },
                callback_entry={"function": "processProposal", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-DIVIDEND-CONFIG",
                vuln_type="Cross-Contract Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Token",
                source_function="approve",
                target_contract="Token",
                target_function="excludeFromDividends",
                key_states={"excludedFromDividends"},
                external_call={"expression": "dividendTracker.excludeFromDividends(pair, true)"},
                callback_entry={"function": "excludeFromDividends", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-TOKEN-LIFECYCLE",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Minter",
                source_function="approveMint",
                target_contract="Minter",
                target_function="approveMint",
                key_states={"pendingMints"},
                external_call={"expression": "token.mint(pendingMints[nonce].to, pendingMints[nonce].tokens)"},
                callback_entry={"function": "approveMint", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-AIRDROP",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Airdrop",
                source_function="airDropSingleAmount",
                target_contract="Airdrop",
                target_function="airDropSingleAmount",
                key_states={"airdrops", "dropAmount"},
                external_call={"expression": "assert(token.transfer(recipient, amount))"},
                callback_entry={"function": "airDropSingleAmount", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-ROUTER-TAX",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Token",
                source_function="transfer",
                target_contract="Token",
                target_function="owner_rescueTokens",
                key_states={"totalTokensFromTax"},
                external_call={
                    "expression": "router.swapExactTokensForETHSupportingFeeOnTransferTokens(amount, 0, path, address(this), block.timestamp)"
                },
                callback_entry={"function": "owner_rescueTokens", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-UNLOCK-HOLDER",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="TokenLock",
                source_function="unlockTokens",
                target_contract="TokenLock",
                target_function="addHolder",
                key_states={"holderList"},
                external_call={"expression": "oppToken.transfer(msg.sender, holderList[msg.sender].tokens)"},
                callback_entry={"function": "addHolder", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-ROUTER-LIQUIDITY",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Token",
                source_function="startTrading",
                target_contract="Token",
                target_function="startTrading",
                key_states={"pair"},
                external_call={
                    "expression": "router.addLiquidityETH{value: ethAmount}(address(this), tokenAmount, 0, 0, owner(), block.timestamp)"
                },
                callback_entry={"function": "startTrading", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-LOG-DELEGATECALL",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Logger",
                source_function="fallback",
                target_contract="Logger",
                target_function="withdrawal",
                key_states={"adr"},
                external_call={"expression": "emails.delegatecall(bytes4(sha3()(logEvent())))"},
                callback_entry={"function": "withdrawal", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-FIXED-DISTRIBUTION",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Airdrop",
                source_function="v1AirdropETH",
                target_contract="Airdrop",
                target_function="v1AirdropETH",
                key_states={"_buyMap"},
                external_call={"expression": "this.transfer(0x4a9a32f8a311884e3844d984779f44c661017647, 1000)"},
                callback_entry={"function": "v1AirdropETH", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-CASH-CHANGE-LOCK",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Sale",
                source_function="orderEmeejis",
                target_contract="Sale",
                target_function="orderEmeejis",
                key_states={"reentrancyLock"},
                external_call={"expression": "msg.sender.call{value: cashChange}()"},
                callback_entry={"function": "orderEmeejis", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-M-TXS",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Wallet",
                source_function="changeOwner",
                target_contract="Wallet",
                target_function="confirm",
                key_states={"m_txs"},
                external_call={"expression": "!_to.call.value(_value)(_data)"},
                callback_entry={"function": "confirm", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-HOLDER-PAYOUT",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="HolderVault",
                source_function="WithdrawToHolder",
                target_contract="HolderVault",
                target_function="WithdrawToHolder",
                key_states={"Holders"},
                external_call={"expression": "_addr.call.value(_wei)()"},
                callback_entry={"function": "WithdrawToHolder", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-TIER-BENEFICIARY",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Sale",
                source_function="buyTokens",
                target_contract="Sale",
                target_function="buyTokens",
                key_states={"tierTotal"},
                external_call={"expression": "token.transfer(beneficiary, tokens)"},
                callback_entry={"function": "buyTokens", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-P3D-DIVIDENDS",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="DividendProxy",
                source_function="sendDividends",
                target_contract="DividendProxy",
                target_function="sendDividends",
                key_states={"totalDividends", "totalDonations"},
                external_call={"expression": "p3d.sell(tokens)"},
                callback_entry={"function": "sendDividends", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-POOL-SUPPORT-FEE",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="PoolRouter",
                source_function="swapNFTforFT",
                target_contract="PoolRouter",
                target_function="withdrawSupportFee",
                key_states={"supporterFee"},
                external_call={"expression": "_paymentToken = IPool(_poolList[i]).paymentToken()"},
                callback_entry={"function": "withdrawSupportFee", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-USER-ACCUMULATOR",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="DepositBook",
                source_function="fallback",
                target_contract="DepositBook",
                target_function="fallback",
                key_states={"users"},
                external_call={
                    "expression": "users[msg.sender].touzizongshu = msg.value.add(users[msg.sender].touzizongshu)"
                },
                callback_entry={"function": "fallback", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-MERCHANT-HISTORY",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Gateway",
                source_function="setMerchantDealsHistory",
                target_contract="Gateway",
                target_function="setMerchantDealsHistory",
                key_states={"merchantHistory"},
                external_call={"expression": "require(_merchantHistory.merchantIdHash() == merchantIdHash)"},
                callback_entry={"function": "setMerchantDealsHistory", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-SALE-MSGSENDER-REWARD",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Sale",
                source_function="fallback",
                target_contract="Sale",
                target_function="checkTargetReached",
                key_states={"amountRaised"},
                external_call={"expression": "tokenReward.transfer(msg.sender, amount / price)"},
                callback_entry={"function": "checkTargetReached", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-MARKETPLACE-INCREMENT",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Market",
                source_function="createMarketItem",
                target_contract="Market",
                target_function="acceptItemOffer",
                key_states={"_status", "idToMarketItem"},
                external_call={"expression": "_itemsSold.increment()"},
                callback_entry={"function": "acceptItemOffer", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-DIVIDEND-CROSS-CONFIG",
                vuln_type="Cross-Contract Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Token",
                source_function="transfer",
                target_contract="DividendTracker",
                target_function="excludeFromDividends",
                key_states={"_owner", "excludedFromDividends"},
                external_call={"expression": "dividendTracker.excludeFromDividends(pair)"},
                callback_entry={"function": "excludeFromDividends", "kind": "cross_contract"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-STATUS-PRICE-CALL",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Market",
                source_function="buyToken",
                target_contract="Market",
                target_function="buyToken",
                key_states={"_status"},
                external_call={"expression": "address(msg.sender).call{value: price}()"},
                callback_entry={"function": "buyToken", "kind": "classic"},
                confidence_score=0.67,
            ),
            VulnerabilityReport(
                vuln_id="CCR-SHITCOIN-OWNER-TRANSFER",
                vuln_type="Classic Reentrancy",
                vuln_family="CCR",
                severity="Medium",
                source_contract="Exchange",
                source_function="trade",
                target_contract="Exchange",
                target_function="buy",
                key_states={"order_book", "shitcoins", "main_fee"},
                external_call={"expression": "require(shitcoin.transfer(make.owner, send_to_maker))"},
                callback_entry={"function": "buy", "kind": "classic"},
                confidence_score=0.67,
            ),
        ]

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports(reports)

        self.assertFalse(kept)
        self.assertEqual(len(dropped), len(reports))
        self.assertTrue(all("strict" in reason for _, reason in dropped))

    def test_strict_classic_policy_keeps_user_controlled_inbound_token_transfer(self):
        report = VulnerabilityReport(
            vuln_id="CCR-USER-INBOUND",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Pool",
            source_function="buyTokenByETH",
            target_contract="Pool",
            target_function="buyTokenByETH",
            key_states={"_actualFund", "_aveCost"},
            external_call={"expression": "_targetToken.safeTransferFrom(msg.sender, address(this), amount)"},
            callback_entry={"function": "buyTokenByETH", "kind": "classic"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertEqual(kept, [report])
        self.assertFalse(dropped)

    def test_strict_policy_drops_weak_ror_bookkeeping_windows(self):
        reports = [
            VulnerabilityReport(
                vuln_id="ROR-INIT-DECIMALS",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Token",
                source_function="intializeContract",
                key_states={"_decimals"},
                query_function="Token.decimals",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-TRANSFER-BALANCES",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Token",
                source_function="_transfer",
                key_states={"_balances"},
                query_function="Token.balanceOf",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-AIRDROP-BUYMAP",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Airdrop",
                source_function="v1AirdropETH",
                key_states={"_buyMap"},
                query_function="Airdrop.bought",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-FALLBACK-BALANCE",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Token",
                source_function="fallback",
                key_states={"balances"},
                query_function="Token.balanceOf",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-CURRENT-ROUND",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Lottery",
                source_function="finalizeRound",
                key_states={"currentRound"},
                query_function="Lottery.currentRound",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-RFT",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="Token",
                source_function="_RFT",
                key_states={"_rOd"},
                query_function="Token.reflectionFromToken",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-DIVIDEND-WITHDRAW",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="DividendPayingToken",
                source_function="_withdrawDividendOfUser",
                key_states={"withdrawnDividends"},
                query_function="DividendPayingToken.withdrawableDividendOf",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
            VulnerabilityReport(
                vuln_id="ROR-DIVIDEND-PROCESS",
                vuln_type="ROR",
                vuln_family="ROR",
                severity="Low",
                source_contract="MRFROGDividendTracker",
                source_function="process",
                key_states={"dividendTracker"},
                query_function="MRFROGDividendTracker.getAccountDividendsInfo",
                sink_function="__external_readonly_consumer__",
                evidence_path=[],
                confidence_score=0.55,
            ),
        ]

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports(reports)

        self.assertFalse(kept)
        self.assertEqual(len(dropped), len(reports))
        self.assertTrue(all("strict ROR bookkeeping" in reason for _, reason in dropped))

    def test_strict_classic_policy_drops_marketplace_status_settlement(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MARKETPLACE-SETTLEMENT",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Marketplace",
            source_function="updatePlatformAccount",
            target_contract="Marketplace",
            target_function="convertReserveAuctionToOffers",
            key_states={"_status"},
            external_call={
                "expression": "_seller.call{value: _paymentAmount - _creatorRoyalties}()"
            },
            callback_entry={"function": "convertReserveAuctionToOffers", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_allowance_decrease_fallback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ALLOWANCE-DECREASE",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="transfer",
            target_contract="Token",
            target_function="decreaseAllowance",
            key_states={"_allowances"},
            external_call={"expression": "recipient.call{value: amount}()"},
            callback_entry={"function": "decreaseAllowance", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_escrow_safe_gas_payout(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ESCROW-SAFE-GAS",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Escrow",
            source_function="accept",
            target_contract="Escrow",
            target_function="cancel",
            key_states={"escrows", "feeFunds"},
            external_call={"expression": "!(addr.call.gas(safeGas).value(value)())"},
            callback_entry={"function": "cancel", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_liquidity_lock_maintenance(self):
        report = VulnerabilityReport(
            vuln_id="CCR-LP-LOCK",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Token",
            source_function="launch",
            target_contract="Token",
            target_function="addLiquidity",
            key_states={"m_liquidity"},
            external_call={
                "expression": "FTPLiqLock(lockSvc).lockTokens(m_uniswapV2Pair, unlockTime, msg.sender)"
            },
            callback_entry={"function": "addLiquidity", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_guarded_transfer_eth(self):
        root = self._workspace_test_dir("guarded_transfer_eth_filter")
        source = root / "GuardedTransferEth.sol"
        source.write_text(
            "\n".join(
                [
                    "contract GuardedTransferEth {",
                    "    modifier onlyOwner() { _; }",
                    "    function transferEth() external onlyOwner {",
                    "        address(msg.sender).call{value: address(this).balance}(\"\");",
                    "    }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )
        report = VulnerabilityReport(
            vuln_id="CCR-GUARDED-TRANSFER-ETH",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="GuardedTransferEth",
            source_function="setTreasury",
            target_contract="GuardedTransferEth",
            target_function="transferEth",
            key_states={"contract_balance"},
            external_call={"expression": "address(msg.sender).call{value: address(this).balance}()"},
            callback_entry={"function": "transferEth", "kind": "classic"},
            evidence_path=[
                {"function": "setTreasury", "line": 2, "file": str(source), "expression": ""},
                {"function": "transferEth", "line": 4, "file": str(source), "expression": ""},
            ],
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_classic_policy_drops_multisig_execution_bookkeeping(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MULTISIG-DAYLIMIT",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Wallet",
            source_function="execute",
            target_contract="Wallet",
            target_function="resetSpentToday",
            key_states={"m_spentToday", "m_pending"},
            external_call={"expression": "_to.call.value(_value)(_data)"},
            callback_entry={"function": "resetSpentToday", "kind": "classic"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict classic fallback", dropped[0][1])

    def test_strict_policy_drops_ror_getmaxbuy_liquidity_configuration(self):
        report = VulnerabilityReport(
            vuln_id="ROR-GETMAXBUY-LIQUIDITY",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="Low",
            source_contract="Token",
            source_function="makeLiquidity",
            key_states={"incrementTime", "maxBuyIncrementValue"},
            query_function="Token.getMaxBuy",
            sink_function="__external_readonly_consumer__",
            evidence_path=[
                {
                    "expression": (
                        "_uniswapV2Router.addLiquidityETH{value: address(this).balance}"
                        "(address(this), _totalSupply, 0, 0, msg.sender, block.timestamp)"
                    )
                }
            ],
            confidence_score=0.55,
        )

        normal_kept, normal_dropped = PrecisionFilter().filter_reports([report])
        strict_kept, strict_dropped = PrecisionFilter(
            classic_fallback_policy="strict"
        ).filter_reports([report])

        self.assertEqual(normal_kept, [report])
        self.assertFalse(normal_dropped)
        self.assertFalse(strict_kept)
        self.assertIn("strict ROR external consumer", strict_dropped[0][1])

    def test_strict_policy_drops_ror_multisig_transaction_query(self):
        report = VulnerabilityReport(
            vuln_id="ROR-MULTISIG-TRANSACTIONS",
            vuln_type="ROR",
            vuln_family="ROR",
            severity="Low",
            source_contract="MultiSigWallet",
            source_function="executeTransaction",
            key_states={"transactions"},
            query_function="MultiSigWallet.getTransactionCount",
            sink_function="__external_readonly_consumer__",
            evidence_path=[
                {"expression": "tx.destination.call.value(tx.value)(tx.data)"}
            ],
            confidence_score=0.55,
        )

        kept, dropped = PrecisionFilter(classic_fallback_policy="strict").filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("strict ROR external consumer", dropped[0][1])

    def test_strict_policy_drops_full_balance_drain_callback(self):
        report = VulnerabilityReport(
            vuln_id="CCR-DRAIN",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Utility",
            source_function="drain",
            target_contract="Utility",
            target_function="drain",
            key_states={"contract_balance"},
            external_call={"expression": "msg.sender.call.value(address(this).balance)()"},
            callback_entry={"function": "drain", "kind": "classic"},
            confidence_score=0.67,
        )

        strict_kept, strict_dropped = PrecisionFilter(
            classic_fallback_policy="strict"
        ).filter_reports([report])
        aggressive_kept, aggressive_dropped = PrecisionFilter(
            classic_fallback_policy="aggressive"
        ).filter_reports([report])

        self.assertFalse(strict_kept)
        self.assertIn("strict classic fallback", strict_dropped[0][1])
        self.assertFalse(aggressive_kept)
        self.assertIn("strict classic fallback", aggressive_dropped[0][1])

    def test_precision_filter_drops_guarded_admin_config_callback(self):
        root = self._workspace_test_dir("guarded_config_filter")
        source = root / "GuardedLaunch.sol"
        source.write_text(
            "\n".join(
                [
                    "contract GuardedLaunch {",
                    "    modifier onlyOwner() { _; }",
                    "    bool public launched;",
                    "    function launch() external onlyOwner returns (bool) {",
                    "        launched = true;",
                    "        return true;",
                    "    }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )
        report = VulnerabilityReport(
            vuln_id="CCR-GUARDED-CONFIG",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="GuardedLaunch",
            source_function="transfer",
            target_contract="GuardedLaunch",
            target_function="launch",
            key_states={"contract_balance"},
            external_call={"expression": "address(msg.sender).call{value: address(this).balance}()"},
            callback_entry={"function": "launch", "kind": "classic"},
            evidence_path=[
                {"function": "transfer", "line": 3, "file": str(source), "expression": ""},
                {"function": "launch", "line": 5, "file": str(source), "expression": "launched = true"},
            ],
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("guarded admin/config", dropped[0][1])

    def test_precision_filter_drops_dex_router_business_call(self):
        report = VulnerabilityReport(
            vuln_id="CCR-ROUTER",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Token",
            source_function="swapBack",
            target_contract="Token",
            target_function="setExcludeFromFee",
            key_states={"_isExcludedFromFee"},
            external_call={
                "expression": (
                    "uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens"
                    "(tokenAmount, 0, path, address(this), block.timestamp)"
                )
            },
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("DEX/router", dropped[0][1])

    def test_precision_filter_drops_token_lifecycle_mint_call(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MINT",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="Medium",
            source_contract="Crowdsale",
            source_function="buyTokens",
            target_contract="Crowdsale",
            target_function="airdropFor",
            key_states={"contributorList"},
            external_call={"expression": "require(bool)(token.mint(_beneficiary, tokens))"},
            confidence_score=0.67,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("crowdsale/token", dropped[0][1])

    def test_precision_filter_drops_multisig_transaction_bookkeeping(self):
        report = VulnerabilityReport(
            vuln_id="CCR-MULTISIG",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="MultiSigWallet",
            source_function="executeTransaction",
            target_contract="MultiSigWallet",
            target_function="confirmTransaction",
            key_states={"transactions"},
            external_call={"expression": "tx.destination.call.value(tx.value)(tx.data)"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([report])

        self.assertFalse(kept)
        self.assertIn("multisig", dropped[0][1])

    def test_precision_filter_keeps_eth_helper_and_business_calls(self):
        eth_helper = VulnerabilityReport(
            vuln_id="CCR-ETH-HELPER",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Pool",
            source_function="withdraw",
            target_contract="Pool",
            target_function="withdraw",
            key_states={"balances"},
            external_call={"expression": "TransferHelper.safeTransferETH(msg.sender, balances[msg.sender])"},
            confidence_score=0.84,
        )
        business_call = VulnerabilityReport(
            vuln_id="CCR-BUSINESS",
            vuln_type="Classic Reentrancy",
            vuln_family="CCR",
            severity="High",
            source_contract="Vault",
            source_function="withdraw",
            target_contract="Vault",
            target_function="withdraw",
            key_states={"vaultDebt"},
            external_call={"expression": "DEX.withdraw(amount)"},
            confidence_score=0.84,
        )

        kept, dropped = PrecisionFilter().filter_reports([eth_helper, business_call])

        self.assertEqual(kept, [eth_helper, business_call])
        self.assertFalse(dropped)

    def test_output_targets_support_directory_and_file_destinations(self):
        root = self._workspace_test_dir("targets")
        directory_targets = resolve_output_targets(str(root / "reports"), write_json=True, write_csv=True)
        self.assertEqual(directory_targets["json"], root / "reports" / "vulnerabilities.json")
        self.assertEqual(directory_targets["csv"], root / "reports" / "vulnerabilities.csv")

        file_targets = resolve_output_targets(str(root / "report.json"), write_json=True, write_csv=True)
        self.assertEqual(file_targets["json"], root / "report.json")
        self.assertEqual(file_targets["csv"], root / "report.csv")

    def test_generate_reports_creates_missing_directory_and_honors_requested_formats(self):
        guardian = ReentrancyGuardian(AnalysisConfig())
        root = self._workspace_test_dir("csv_only")
        target_dir = root / "nested" / "reports"
        targets = guardian.generate_reports(
            {"all_reports": [self._sample_report()]},
            str(target_dir),
            write_json=False,
            write_csv=True,
        )

        csv_path = targets["csv"]
        self.assertTrue(csv_path.exists())
        self.assertFalse((target_dir / "vulnerabilities.json").exists())

        csv_text = csv_path.read_text(encoding="utf-8")
        self.assertIn("target_function", csv_text)
        self.assertIn("withdraw", csv_text)

    def test_generate_reports_supports_explicit_report_file_path(self):
        guardian = ReentrancyGuardian(AnalysisConfig())
        root = self._workspace_test_dir("file_output")
        report_file = root / "custom" / "report.json"
        targets = guardian.generate_reports(
            {"all_reports": [self._sample_report()]},
            str(report_file),
            write_json=True,
            write_csv=True,
        )

        self.assertTrue(targets["json"].exists())
        self.assertTrue(targets["csv"].exists())

        data = json.loads(targets["json"].read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["total_vulnerabilities"], 1)
        self.assertEqual(data["summary"]["classic_reentrancy_count"], 0)
        self.assertEqual(data["summary"]["cross_contract_reentrancy_count"], 0)

    def test_guardian_validator_uses_configured_timeout(self):
        _, builder, _, lock, _ = self._build_pipeline(str(ROOT / "benchmarks" / "ConstraintSample.sol"))
        config = AnalysisConfig()
        config.timeout = 7
        guardian = ReentrancyGuardian(config)
        guardian.icfg = {
            "builder": builder,
            "lock": lock,
        }

        validator = guardian._create_validator()
        self.assertEqual(validator.path_solver.timeout_ms, 7000)


if __name__ == "__main__":
    unittest.main()
