#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import CCRCandidate, RORCandidate, VulnerabilityReport


class Merger:
    """Merge exact-duplicate and near-duplicate vulnerability reports."""

    SIMILARITY_THRESHOLD = 0.78

    def __init__(self):
        self.merged_results: List[VulnerabilityReport] = []

    def merge_candidates(
        self,
        ccr_candidates: List[CCRCandidate],
        ror_candidates: List[RORCandidate],
    ) -> List[Tuple[Any, Any]]:
        merged = []
        for candidate in ccr_candidates:
            merged.append((candidate, getattr(candidate, "confidence", 0.5)))
        for candidate in ror_candidates:
            merged.append((candidate, getattr(candidate, "confidence", 0.5)))
        merged.sort(key=lambda item: item[1], reverse=True)
        return merged

    def merge_duplicate_vulnerabilities(self, vulns: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        merged: List[VulnerabilityReport] = []

        for vuln in sorted(
            vulns,
            key=lambda report: (
                self._severity_rank(report.severity),
                report.confidence_score,
                len(report.key_states),
            ),
            reverse=True,
        ):
            best_index = self._find_similar_report_index(merged, vuln)
            if best_index is None:
                merged.append(vuln)
            else:
                merged[best_index] = self._merge_two_vulnerabilities(merged[best_index], vuln)

        self.merged_results = merged
        return merged

    def _find_similar_report_index(
        self,
        merged: List[VulnerabilityReport],
        candidate: VulnerabilityReport,
    ) -> Optional[int]:
        best_index: Optional[int] = None
        best_score = 0.0

        for index, existing in enumerate(merged):
            if not self._is_same_merge_family(existing, candidate):
                continue

            score = self._similarity_score(existing, candidate)
            if score >= self.SIMILARITY_THRESHOLD and score > best_score:
                best_index = index
                best_score = score

        return best_index

    def _is_same_merge_family(self, vuln1: VulnerabilityReport, vuln2: VulnerabilityReport) -> bool:
        if vuln1.vuln_family == "ROR" or vuln2.vuln_family == "ROR":
            return (
                vuln1.vuln_type == vuln2.vuln_type
                and vuln1.source_contract == vuln2.source_contract
                and vuln1.source_function == vuln2.source_function
                and vuln1.query_function == vuln2.query_function
                and vuln1.sink_function == vuln2.sink_function
            )
        return (
            vuln1.vuln_type == vuln2.vuln_type
            and vuln1.source_contract == vuln2.source_contract
            and vuln1.source_function == vuln2.source_function
        )

    def _similarity_score(self, vuln1: VulnerabilityReport, vuln2: VulnerabilityReport) -> float:
        if not self._is_same_merge_family(vuln1, vuln2):
            return 0.0

        score = 0.4

        score += 0.2 * self._set_jaccard(set(vuln1.key_states), set(vuln2.key_states))
        score += 0.1 * self._set_jaccard(self._evidence_node_ids(vuln1), self._evidence_node_ids(vuln2))
        score += 0.15 * self._anchor_similarity(vuln1, vuln2)
        score += 0.15 * self._flow_endpoint_similarity(vuln1, vuln2)

        return min(1.0, score)

    def _anchor_similarity(self, vuln1: VulnerabilityReport, vuln2: VulnerabilityReport) -> float:
        anchor1 = self._primary_anchor_node(vuln1)
        anchor2 = self._primary_anchor_node(vuln2)
        if anchor1 is None or anchor2 is None:
            return 0.5 if anchor1 == anchor2 else 0.0

        distance = abs(anchor1 - anchor2)
        if distance == 0:
            return 1.0
        if distance <= 2:
            return 0.85
        if distance <= 5:
            return 0.6
        return 0.0

    def _flow_endpoint_similarity(self, vuln1: VulnerabilityReport, vuln2: VulnerabilityReport) -> float:
        score = 0.0

        if vuln1.is_ccr():
            if vuln1.target_contract == vuln2.target_contract:
                score += 0.4
            if vuln1.target_function == vuln2.target_function:
                score += 0.4
            callback1 = str((vuln1.callback_entry or {}).get("function", ""))
            callback2 = str((vuln2.callback_entry or {}).get("function", ""))
            if callback1 and callback1 == callback2:
                score += 0.2
            return min(1.0, score)

        if vuln1.query_function == vuln2.query_function:
            score += 0.45
        if vuln1.sink_function == vuln2.sink_function:
            score += 0.45

        sink_node_1 = int((vuln1.sink_node or {}).get("node_id", 0) or 0)
        sink_node_2 = int((vuln2.sink_node or {}).get("node_id", 0) or 0)
        if sink_node_1 and sink_node_2:
            score += 0.1 if abs(sink_node_1 - sink_node_2) <= 2 else 0.0

        return min(1.0, score)

    def _merge_two_vulnerabilities(
        self,
        vuln1: VulnerabilityReport,
        vuln2: VulnerabilityReport,
    ) -> VulnerabilityReport:
        best = vuln1
        other = vuln2

        if self._severity_rank(vuln2.severity) > self._severity_rank(vuln1.severity):
            best, other = vuln2, vuln1
        elif vuln2.confidence_score > vuln1.confidence_score:
            best, other = vuln2, vuln1

        best.key_states = set(best.key_states) | set(other.key_states)
        best.overlap_states = set(best.overlap_states) | set(other.overlap_states)
        best.evidence_path = list(best.evidence_path) + [
            path for path in other.evidence_path if path not in best.evidence_path
        ]
        best.propagation_path = self._merge_node_paths(best.propagation_path, other.propagation_path)
        best.confidence_score = max(best.confidence_score, other.confidence_score)

        if not best.reason and other.reason:
            best.reason = other.reason
        if not best.target_contract and other.target_contract:
            best.target_contract = other.target_contract
        if not best.target_function and other.target_function:
            best.target_function = other.target_function
        if not best.query_function and other.query_function:
            best.query_function = other.query_function
        if not best.sink_function and other.sink_function:
            best.sink_function = other.sink_function
        if not best.external_call and other.external_call:
            best.external_call = dict(other.external_call)
        if not best.callback_entry and other.callback_entry:
            best.callback_entry = dict(other.callback_entry)
        if not best.mismatch_window and other.mismatch_window:
            best.mismatch_window = dict(other.mismatch_window)
        if not best.query_node and other.query_node:
            best.query_node = dict(other.query_node)
        if not best.sink_node and other.sink_node:
            best.sink_node = dict(other.sink_node)

        if other.code_locations:
            merged_locations = dict(best.code_locations)
            merged_locations.update(other.code_locations)
            best.code_locations = merged_locations

        return best

    def deduplicate_candidates(self, candidates: List[Any]) -> List[Any]:
        dedup: Dict[str, Any] = {}
        for candidate in candidates:
            candidate_id = getattr(candidate, "candidate_id", repr(candidate))
            if candidate_id not in dedup:
                dedup[candidate_id] = candidate
                continue

            current = dedup[candidate_id]
            if getattr(candidate, "confidence", 0.0) > getattr(current, "confidence", 0.0):
                dedup[candidate_id] = candidate

        return list(dedup.values())

    def get_merged_results(self) -> List[VulnerabilityReport]:
        return self.merged_results

    def _primary_anchor_node(self, vuln: VulnerabilityReport) -> Optional[int]:
        if vuln.external_call and "node_id" in vuln.external_call:
            return int(vuln.external_call["node_id"])
        if vuln.mismatch_window and "external_call_node_id" in vuln.mismatch_window:
            return int(vuln.mismatch_window["external_call_node_id"])
        evidence_nodes = sorted(self._evidence_node_ids(vuln))
        return evidence_nodes[0] if evidence_nodes else None

    def _evidence_node_ids(self, vuln: VulnerabilityReport) -> Set[int]:
        result: Set[int] = set()
        for item in vuln.evidence_path:
            node_id = item.get("node_id") if isinstance(item, dict) else None
            if isinstance(node_id, int):
                result.add(node_id)
        return result

    def _merge_node_paths(self, left: List[int], right: List[int]) -> List[int]:
        merged: List[int] = []
        for node_id in list(left) + list(right):
            if node_id not in merged:
                merged.append(node_id)
        return merged

    def _set_jaccard(self, left: Set[Any], right: Set[Any]) -> float:
        if not left and not right:
            return 1.0
        return len(left & right) / max(1, len(left | right))

    def _severity_rank(self, severity: str) -> int:
        return {"Low": 1, "Medium": 2, "High": 3}.get(severity, 0)
