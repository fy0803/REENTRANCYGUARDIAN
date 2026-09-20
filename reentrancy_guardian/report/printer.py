#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List

from models.report import VulnerabilityReport


class ConsolePrinter:
    """Small ASCII-only console printer."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def print_header(self) -> None:
        print("=" * 70)
        print("  Reentrancy Guardian - Semantic ICFG Reentrancy Detector")
        print("=" * 70)

    def print_progress(self, stage: str, progress: int, total: int) -> None:
        percent = (progress / total * 100) if total else 0
        print(f"[{percent:.1f}%] {stage}: {progress}/{total}")

    def print_summary(self, reports: List[VulnerabilityReport]) -> None:
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        ccr_reports = [r for r in reports if r.is_ccr()]
        ror_reports = [r for r in reports if r.is_ror()]
        classic_reports = [r for r in ccr_reports if r.vuln_type == "Classic Reentrancy"]
        cross_contract_reports = [r for r in ccr_reports if r.vuln_type == "Cross-Contract Reentrancy"]
        print(f"Total Vulnerabilities Found: {len(reports)}")
        print(f"  - Classic Reentrancy: {len(classic_reports)}")
        print(f"  - Cross-Contract Reentrancy: {len(cross_contract_reports)}")
        print(f"  - ROR: {len(ror_reports)}")

    def print_vulnerabilities(self, reports: List[VulnerabilityReport]) -> None:
        if not reports:
            print("\n[OK] No vulnerabilities found")
            return
        print("\n" + "=" * 70)
        print("VULNERABILITIES")
        print("=" * 70)
        for index, report in enumerate(reports, start=1):
            print(f"\n[{index}] {report.vuln_id}")
            print(f"    Type:     {report.display_type()}")
            print(f"    Severity: {report.severity}")
            print(f"    Source:   {report.source_contract}.{report.source_function}")
            if report.target_contract and report.target_function:
                print(f"    Target:   {report.target_contract}.{report.target_function}")
            if report.query_function:
                print(f"    Query:    {report.query_function}")
            if report.sink_function:
                print(f"    Sink:     {report.sink_function}")
            if report.key_states:
                print(f"    States:   {', '.join(sorted(report.key_states))}")
            if report.reason:
                print(f"    Reason:   {report.reason}")

    def print_error(self, message: str) -> None:
        print(f"[ERROR] {message}")

    def print_warning(self, message: str) -> None:
        if self.verbose:
            print(f"[WARNING] {message}")
