#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reentrancy_guardian"))

from config import AnalysisConfig
from main import ReentrancyGuardian, setup_logging


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    title: str
    path: str
    goal: str
    expected_labels: tuple[str, ...] = ()
    expected_total: int | None = None


CASE_SPECS: tuple[CaseSpec, ...] = (
    CaseSpec(
        case_id="balanced_safe",
        title="Balanced sample stays clean",
        path="benchmarks/BalancedSample.sol",
        goal="Negative control: balanced state updates should not trigger CCR or ROR findings.",
        expected_total=0,
    ),
    CaseSpec(
        case_id="semantic_icfg_combo",
        title="Classic plus ROR combo",
        path="benchmarks/SemanticICFGSample.sol",
        goal="Positive control: detect classic reentrancy and read-only reentrancy in one sample.",
        expected_labels=("Classic Reentrancy", "ROR"),
    ),
    CaseSpec(
        case_id="cross_contract_labels",
        title="Cross-contract labeling",
        path="benchmarks/CrossContractLabelSample.sol",
        goal="Show that a resolved cross-contract callback is labeled separately while the classic fallback remains visible.",
        expected_labels=("Classic Reentrancy", "Cross-Contract Reentrancy"),
    ),
    CaseSpec(
        case_id="balance_dependent",
        title="Balance-dependent classic reentrancy",
        path="benchmarks/BalanceDependentReentrancySample.sol",
        goal="Validate detection when the overlapping state is the contract balance rather than a normal storage slot.",
        expected_labels=("Classic Reentrancy",),
    ),
    CaseSpec(
        case_id="modifier_based",
        title="Modifier-based reentrancy",
        path="contracts/smartbugs/modifier_reentrancy/modifier_reentrancy.sol",
        goal="Validate detection through modifier-driven control flow.",
        expected_labels=("Classic Reentrancy",),
    ),
    CaseSpec(
        case_id="legacy_low_level_call",
        title="Legacy low-level call compatibility",
        path="contracts/smartbugs/reentrancy_insecure/reentrancy_insecure.sol",
        goal="Exercise the compatibility rewrite path and still recover the classic reentrancy finding.",
        expected_labels=("Classic Reentrancy",),
    ),
    CaseSpec(
        case_id="interprocedural_bonus",
        title="Interprocedural bonus pattern",
        path="contracts/smartbugs/reentrancy_bonus/reentrancy_bonus.sol",
        goal="Validate interprocedural classic reentrancy detection on a SmartBugs sample.",
        expected_labels=("Classic Reentrancy",),
    ),
    CaseSpec(
        case_id="unsat_ror_filtered",
        title="Unsat ROR is filtered",
        path="benchmarks/UnsatRORSample.sol",
        goal="Show that infeasible ROR propagation is filtered while an independent classic reentrancy finding can still remain.",
        expected_labels=("Classic Reentrancy",),
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a small-sample qualitative validation suite for Reentrancy Guardian."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=str(ROOT / "results" / "functional_validation"),
        help="Directory used for per-case reports and the suite summary.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Analysis timeout in seconds passed to the validator.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging inside the detector.",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="selected_cases",
        help="Run only the named case id. Can be supplied multiple times.",
    )
    return parser.parse_args()


def select_cases(selected_cases: Iterable[str] | None) -> list[CaseSpec]:
    if not selected_cases:
        return list(CASE_SPECS)

    wanted = set(selected_cases)
    cases = [case for case in CASE_SPECS if case.case_id in wanted]
    missing = sorted(wanted - {case.case_id for case in cases})
    if missing:
        raise SystemExit(f"Unknown case ids: {', '.join(missing)}")
    return cases


def build_guardian(timeout: int, verbose: bool) -> ReentrancyGuardian:
    config = AnalysisConfig()
    config.timeout = timeout
    config.verbose = verbose
    return ReentrancyGuardian(config)


def expected_text(case: CaseSpec) -> str:
    if case.expected_total == 0:
        return "No findings"
    if case.expected_labels:
        return ", ".join(case.expected_labels)
    return "Custom expectation"


def summarize_findings(all_reports: list) -> list[dict]:
    findings: list[dict] = []
    for report in all_reports:
        findings.append(
            {
                "type": report.vuln_type,
                "severity": report.severity,
                "source": f"{report.source_contract}.{report.source_function}",
                "target": (
                    f"{report.target_contract}.{report.target_function}"
                    if report.target_contract and report.target_function
                    else None
                ),
                "query": report.query_function,
                "sink": report.sink_function,
                "reason": report.reason,
            }
        )
    return findings


def evaluate_case(case: CaseSpec, labels: list[str], total_findings: int) -> tuple[bool, str]:
    counter = Counter(labels)

    if case.expected_total == 0:
        passed = total_findings == 0
        detail = "No findings as expected." if passed else f"Expected 0 findings, got {total_findings}."
        return passed, detail

    missing_labels = [label for label in case.expected_labels if counter[label] == 0]
    if missing_labels:
        return False, f"Missing expected labels: {', '.join(missing_labels)}."

    return True, f"Observed expected labels: {', '.join(case.expected_labels)}."


def write_summary_markdown(output_path: Path, suite_summary: dict) -> None:
    lines: list[str] = []
    lines.append("# Functional Validation Summary")
    lines.append("")
    lines.append(f"- Generated by `scripts/run_qualitative_validation.py`")
    lines.append(f"- Cases run: {suite_summary['cases_run']}")
    lines.append(f"- Cases passed: {suite_summary['cases_passed']}")
    lines.append(f"- Cases failed: {suite_summary['cases_failed']}")
    lines.append("")
    lines.append("| Case | Goal | Expected | Actual | Runtime (s) | Status |")
    lines.append("| --- | --- | --- | --- | ---: | --- |")

    for case in suite_summary["cases"]:
        actual = "No findings" if case["total_findings"] == 0 else ", ".join(case["labels_found"])
        status = "PASS" if case["passed"] else "FAIL"
        lines.append(
            f"| `{case['case_id']}` | {case['goal']} | {case['expected']} | {actual} | "
            f"{case['runtime_seconds']:.3f} | {status} |"
        )

    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")

    for case in suite_summary["cases"]:
        lines.append(f"### {case['case_id']}: {case['title']}")
        lines.append("")
        lines.append(f"- Input: `{case['input_path']}`")
        lines.append(f"- Goal: {case['goal']}")
        lines.append(f"- Expected: {case['expected']}")
        lines.append(f"- Actual: {'No findings' if case['total_findings'] == 0 else ', '.join(case['labels_found'])}")
        lines.append(f"- Runtime: {case['runtime_seconds']:.3f} s")
        lines.append(f"- Check: {case['check_message']}")
        lines.append(f"- Report directory: `{case['report_dir']}`")
        lines.append("")

        if case["findings"]:
            for finding in case["findings"]:
                target_text = ""
                if finding["target"]:
                    target_text = f", target `{finding['target']}`"
                elif finding["query"] and finding["sink"]:
                    target_text = f", query `{finding['query']}` -> sink `{finding['sink']}`"
                lines.append(
                    f"- {finding['type']} ({finding['severity']}): source `{finding['source']}`{target_text}. "
                    f"Reason: {finding['reason']}"
                )
        else:
            lines.append("- No findings.")

        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    cases = select_cases(args.selected_cases)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(args.verbose)

    suite_results: list[dict] = []

    for case in cases:
        input_path = ROOT / case.path
        report_dir = output_dir / case.case_id

        guardian = build_guardian(timeout=args.timeout, verbose=args.verbose)

        print(f"\n=== Running case: {case.case_id} ===")
        start = perf_counter()
        results = guardian.analyze(str(input_path))
        runtime_seconds = perf_counter() - start

        guardian.generate_reports(
            results,
            str(report_dir),
            write_json=True,
            write_csv=True,
        )

        all_reports = results.get("all_reports", [])
        labels_found = [report.vuln_type for report in all_reports]
        total_findings = len(all_reports)
        passed, check_message = evaluate_case(case, labels_found, total_findings)

        suite_results.append(
            {
                "case_id": case.case_id,
                "title": case.title,
                "input_path": case.path,
                "goal": case.goal,
                "expected": expected_text(case),
                "labels_found": labels_found,
                "total_findings": total_findings,
                "runtime_seconds": runtime_seconds,
                "passed": passed,
                "check_message": check_message,
                "findings": summarize_findings(all_reports),
                "report_dir": str(report_dir.relative_to(ROOT)),
            }
        )

    cases_passed = sum(1 for case in suite_results if case["passed"])
    suite_summary = {
        "cases_run": len(suite_results),
        "cases_passed": cases_passed,
        "cases_failed": len(suite_results) - cases_passed,
        "cases": suite_results,
    }

    summary_json = output_dir / "summary.json"
    summary_md = output_dir / "summary.md"
    summary_json.write_text(json.dumps(suite_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_summary_markdown(summary_md, suite_summary)

    print("\n=== Suite Summary ===")
    print(f"Cases run:    {suite_summary['cases_run']}")
    print(f"Cases passed: {suite_summary['cases_passed']}")
    print(f"Cases failed: {suite_summary['cases_failed']}")
    print(f"Summary JSON: {summary_json}")
    print(f"Summary MD:   {summary_md}")

    return 0 if suite_summary["cases_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
