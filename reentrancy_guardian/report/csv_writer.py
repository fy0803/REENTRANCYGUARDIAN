#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import sys
from pathlib import Path as PathlibPath
from typing import Any, Dict, List

sys.path.insert(0, str(PathlibPath(__file__).parent.parent))

from models.report import VulnerabilityReport


class CSVReportWriter:
    SUMMARY_FIELDS = [
        "vuln_id",
        "vuln_type",
        "vuln_family",
        "severity",
        "source_contract",
        "source_function",
        "target_contract",
        "target_function",
        "reason",
    ]

    DETAILED_FIELDS = SUMMARY_FIELDS + [
        "key_states",
        "query_function",
        "sink_function",
        "confidence",
    ]

    def write_summary(self, reports: List[VulnerabilityReport], output_file: str):
        PathlibPath(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.SUMMARY_FIELDS)
            writer.writeheader()
            for report in reports:
                writer.writerow(self._report_to_summary_row(report))

    def write_detailed(self, reports: List[VulnerabilityReport], output_file: str):
        PathlibPath(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.DETAILED_FIELDS)
            writer.writeheader()
            for report in reports:
                writer.writerow(self._report_to_detailed_row(report))

    def _report_to_summary_row(self, report: VulnerabilityReport) -> Dict[str, Any]:
        return {
            "vuln_id": report.vuln_id,
            "vuln_type": report.display_type(),
            "vuln_family": report.vuln_family,
            "severity": report.severity,
            "source_contract": report.source_contract,
            "source_function": report.source_function,
            "target_contract": report.target_contract or "",
            "target_function": report.target_function or "",
            "reason": report.reason,
        }

    def _report_to_detailed_row(self, report: VulnerabilityReport) -> Dict[str, Any]:
        row = self._report_to_summary_row(report)
        row.update(
            {
                "key_states": ";".join(sorted(report.key_states)),
                "query_function": report.query_function or "",
                "sink_function": report.sink_function or "",
                "confidence": f"{report.confidence_score:.2f}",
            }
        )
        return row
