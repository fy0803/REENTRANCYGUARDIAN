#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from pathlib import Path
from pathlib import Path as PathlibPath
from typing import Any, Dict, List

sys.path.insert(0, str(PathlibPath(__file__).parent.parent))

from models.report import VulnerabilityReport


class JSONReportWriter:
    def __init__(self, indent: int = 2):
        self.indent = indent

    def write_reports(self, reports: List[VulnerabilityReport], output_file: str):
        data = {
            "metadata": {
                "tool": "Reentrancy Guardian",
                "version": "0.1.0",
                "report_type": "Vulnerability Report",
                "timestamp": str(__import__("datetime").datetime.now()),
            },
            "summary": {
                "total_vulnerabilities": len(reports),
                "ccr_count": sum(1 for report in reports if report.is_ccr()),
                "classic_reentrancy_count": sum(
                    1 for report in reports if report.vuln_type == "Classic Reentrancy"
                ),
                "cross_contract_reentrancy_count": sum(
                    1 for report in reports if report.vuln_type == "Cross-Contract Reentrancy"
                ),
                "ror_count": sum(1 for report in reports if report.is_ror()),
                "high_severity": sum(1 for report in reports if report.severity == "High"),
                "medium_severity": sum(1 for report in reports if report.severity == "Medium"),
                "low_severity": sum(1 for report in reports if report.severity == "Low"),
            },
            "vulnerabilities": [self._report_to_dict(report) for report in reports],
        }

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=self.indent, ensure_ascii=False)

        print(f"[+] JSON report saved to: {output_file}")

    def _report_to_dict(self, report: VulnerabilityReport) -> Dict[str, Any]:
        return {
            "vuln_id": report.vuln_id,
            "vuln_type": report.vuln_type,
            "vuln_family": report.vuln_family,
            "severity": report.severity,
            "source_contract": report.source_contract,
            "source_function": report.source_function,
            "target_contract": report.target_contract,
            "target_function": report.target_function,
            "key_states": list(report.key_states),
            "external_call": report.external_call,
            "callback_entry": report.callback_entry,
            "mismatch_window": report.mismatch_window,
            "query_function": report.query_function,
            "sink_function": report.sink_function,
            "reason": report.reason,
            "confidence": report.confidence_score,
            "evidence_path": report.evidence_path,
        }

    def write_brief_report(self, reports: List[VulnerabilityReport], output_file: str):
        brief_reports = [
            {
                "index": index + 1,
                "vuln_id": report.vuln_id,
                "type": report.display_type(),
                "family": report.vuln_family,
                "severity": report.severity,
                "location": f"{report.source_contract}.{report.source_function}()",
                "reason": report.reason,
            }
            for index, report in enumerate(reports)
        ]

        data = {
            "total": len(reports),
            "vulnerabilities": brief_reports,
        }

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=self.indent, ensure_ascii=False)
