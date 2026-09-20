#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter, sleep
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = ROOT / "datasets" / "smartbugs-curated" / "dataset"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "smartbugs_negative_eval"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"


@dataclass(frozen=True)
class NegativeCase:
    case_id: str
    category: str
    contract_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Reentrancy Guardian on the non-reentrancy categories of SmartBugs Curated "
            "and generate false-positive tables."
        )
    )
    parser.add_argument(
        "--dataset-dir",
        default=str(DEFAULT_DATASET_DIR),
        help="Path to smartbugs-curated/dataset.",
    )
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--exclude-category",
        action="append",
        default=["reentrancy"],
        help="Dataset category to exclude. Defaults to reentrancy.",
    )
    parser.add_argument("--category", action="append", help="Run only this category. Can be supplied multiple times.")
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run only this case id.")
    parser.add_argument("--limit", type=int, help="Maximum number of negative samples to evaluate.")
    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=120,
        help="Seconds passed to the detector's internal path feasibility timeout.",
    )
    parser.add_argument(
        "--process-timeout",
        type=int,
        default=300,
        help="Hard timeout in seconds for each contract process.",
    )
    parser.add_argument(
        "--bounded-ccr",
        action="store_true",
        help="Enable reduced-precision CCR limits for large-contract coverage diagnostics.",
    )
    parser.add_argument(
        "--ccr-state-limit",
        type=int,
        help="Maximum execution states explored per CCR reachability query in bounded mode.",
    )
    parser.add_argument(
        "--ccr-time-budget",
        type=int,
        help="Maximum seconds spent in CCR detection in bounded mode.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(2, os.cpu_count() or 1)),
        help="Number of parallel contract analyses.",
    )
    parser.add_argument("--force", action="store_true", help="Re-run cases even if cached records exist.")
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def trim_text(text: Optional[str], limit: int = 2000) -> Optional[str]:
    if not text:
        return None
    compact = text.strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 15] + "\n...[truncated]"


def safe_remove_tree(path: Path, allowed_root: Path) -> None:
    resolved_path = path.resolve()
    resolved_root = allowed_root.resolve()
    if resolved_path == resolved_root or resolved_root not in resolved_path.parents:
        raise RuntimeError(f"Refusing to remove path outside output directory: {resolved_path}")
    shutil.rmtree(resolved_path, ignore_errors=True)


def collect_cases(
    dataset_dir: Path,
    excluded_categories: set[str],
    selected_categories: Optional[set[str]],
    selected_case_ids: Optional[set[str]],
    limit: Optional[int],
) -> list[NegativeCase]:
    cases: list[NegativeCase] = []
    for category_dir in sorted(dataset_dir.iterdir(), key=lambda path: path.name.lower()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        if category in excluded_categories:
            continue
        if selected_categories and category not in selected_categories:
            continue

        for contract_path in sorted(category_dir.rglob("*.sol"), key=lambda path: str(path).lower()):
            case_id = f"{category}__{contract_path.stem}"
            if selected_case_ids and case_id not in selected_case_ids:
                continue
            cases.append(NegativeCase(case_id=case_id, category=category, contract_path=contract_path))

    missing = sorted((selected_case_ids or set()) - {case.case_id for case in cases})
    if missing:
        raise SystemExit(f"Unknown negative case ids: {', '.join(missing)}")

    if limit is not None:
        cases = cases[:limit]
    return cases


def build_command(case: NegativeCase, report_dir: Path, args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-u",
        str(MAIN_SCRIPT),
        str(case.contract_path),
        "--json",
        "--csv",
        "-o",
        str(report_dir),
        "--timeout",
        str(args.analysis_timeout),
    ]
    if args.bounded_ccr:
        command.append("--bounded-ccr")
        if args.ccr_state_limit:
            command.extend(["--ccr-state-limit", str(args.ccr_state_limit)])
        if args.ccr_time_budget:
            command.extend(["--ccr-time-budget", str(args.ccr_time_budget)])
    return command


def run_with_live_log(cmd: list[str], log_path: Path, timeout_seconds: int) -> tuple[str, Optional[str], Optional[str]]:
    output_lines: list[str] = []
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
        process = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )

        def reader() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                output_lines.append(line)
                log_handle.write(line)
                log_handle.flush()

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()

        deadline = perf_counter() + timeout_seconds
        while process.poll() is None and perf_counter() < deadline:
            sleep(0.2)

        timed_out = process.poll() is None
        if timed_out:
            process.kill()

        reader_thread.join(timeout=5)
        return_code = process.poll()

    output = "".join(output_lines)
    if timed_out:
        return "timeout", output, f"Process timeout after {timeout_seconds}s"
    if return_code != 0:
        return "analysis_failed", output, output
    return "ok", output, None


def load_report(report_dir: Path) -> dict[str, Any]:
    report_path = report_dir / "vulnerabilities.json"
    if not report_path.exists():
        return {}
    return json.loads(report_path.read_text(encoding="utf-8"))


def summarize_report(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    vulnerabilities = report.get("vulnerabilities") or []
    vuln_types = sorted({str(item.get("vuln_type", "")) for item in vulnerabilities if item.get("vuln_type")})
    severities = sorted({str(item.get("severity", "")) for item in vulnerabilities if item.get("severity")})
    return {
        "total_vulnerabilities": int(summary.get("total_vulnerabilities") or 0),
        "classic_reentrancy_count": int(summary.get("classic_reentrancy_count") or 0),
        "cross_contract_reentrancy_count": int(summary.get("cross_contract_reentrancy_count") or 0),
        "ror_count": int(summary.get("ror_count") or 0),
        "high_severity": int(summary.get("high_severity") or 0),
        "medium_severity": int(summary.get("medium_severity") or 0),
        "low_severity": int(summary.get("low_severity") or 0),
        "vuln_types": "; ".join(vuln_types),
        "severities": "; ".join(severities),
    }


def evaluate_case(case: NegativeCase, args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    report_dir = output_dir / "reports" / case.case_id
    record_path = output_dir / "records" / f"{case.case_id}.json"
    if record_path.exists() and not args.force:
        return json.loads(record_path.read_text(encoding="utf-8"))

    report_dir.parent.mkdir(parents=True, exist_ok=True)
    record_path.parent.mkdir(parents=True, exist_ok=True)
    if report_dir.exists():
        safe_remove_tree(report_dir, output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    started = perf_counter()
    status = "ok"
    error: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    raw_log_path = report_dir / "raw.log"
    status, stdout, error = run_with_live_log(build_command(case, report_dir, args), raw_log_path, args.process_timeout)
    error = trim_text(error)

    runtime_seconds = perf_counter() - started
    report = load_report(report_dir) if status == "ok" else {}
    report_summary = summarize_report(report)
    false_positive = status == "ok" and report_summary["total_vulnerabilities"] > 0

    record = {
        "case_id": case.case_id,
        "category": case.category,
        "input_path": display_path(case.contract_path),
        "status": status,
        "false_positive": int(false_positive),
        "bounded_ccr": int(bool(args.bounded_ccr)),
        "bounded_ccr_truncated": int(bool(stdout and "Bounded CCR detection reached" in stdout)),
        "runtime_seconds": runtime_seconds,
        "report_dir": display_path(report_dir),
        "raw_log": display_path(raw_log_path),
        "error": error,
        "stdout": trim_text(stdout),
        "stderr": trim_text(stderr),
        **report_summary,
    }
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return record


def write_predictions_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "category",
        "input_path",
        "status",
        "false_positive",
        "bounded_ccr",
        "bounded_ccr_truncated",
        "total_vulnerabilities",
        "classic_reentrancy_count",
        "cross_contract_reentrancy_count",
        "ror_count",
        "high_severity",
        "medium_severity",
        "low_severity",
        "vuln_types",
        "severities",
        "runtime_seconds",
        "report_dir",
        "raw_log",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field) for field in fieldnames})


def compute_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_cases = len(records)
    ok_cases = sum(1 for record in records if record["status"] == "ok")
    false_positive_cases = sum(int(record["false_positive"]) for record in records)
    true_negative_cases = sum(1 for record in records if record["status"] == "ok" and not int(record["false_positive"]))
    failed_cases = sum(1 for record in records if record["status"] == "analysis_failed")
    timeout_cases = sum(1 for record in records if record["status"] == "timeout")
    avg_runtime = (
        sum(float(record["runtime_seconds"]) for record in records if record["status"] == "ok") / ok_cases
        if ok_cases
        else None
    )

    by_category: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["category"]].append(record)

    for category, category_records in sorted(grouped.items()):
        category_ok = sum(1 for record in category_records if record["status"] == "ok")
        category_fp = sum(int(record["false_positive"]) for record in category_records)
        by_category[category] = {
            "cases": len(category_records),
            "analyzed": category_ok,
            "false_positives": category_fp,
            "true_negatives": sum(
                1 for record in category_records if record["status"] == "ok" and not int(record["false_positive"])
            ),
            "failed": sum(1 for record in category_records if record["status"] == "analysis_failed"),
            "timeout": sum(1 for record in category_records if record["status"] == "timeout"),
            "fpr_analyzed": category_fp / category_ok if category_ok else None,
        }

    return {
        "total_cases": total_cases,
        "ok_cases": ok_cases,
        "false_positive_cases": false_positive_cases,
        "true_negative_cases": true_negative_cases,
        "analysis_failed_cases": failed_cases,
        "timeout_cases": timeout_cases,
        "total_findings": sum(int(record["total_vulnerabilities"]) for record in records),
        "bounded_ccr_cases": sum(int(record.get("bounded_ccr") or 0) for record in records),
        "bounded_ccr_truncated_cases": sum(int(record.get("bounded_ccr_truncated") or 0) for record in records),
        "classic_reentrancy_findings": sum(int(record["classic_reentrancy_count"]) for record in records),
        "cross_contract_reentrancy_findings": sum(int(record["cross_contract_reentrancy_count"]) for record in records),
        "ror_findings": sum(int(record["ror_count"]) for record in records),
        "fpr_analyzed": false_positive_cases / ok_cases if ok_cases else None,
        "fpr_all": false_positive_cases / total_cases if total_cases else None,
        "avg_runtime_seconds": avg_runtime,
        "status_summary": {
            status: sum(1 for record in records if record["status"] == status)
            for status in sorted({str(record["status"]) for record in records})
        },
        "by_category": by_category,
    }


def format_rate(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def write_summary_markdown(path: Path, summary: dict[str, Any], records: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    lines.append("# SmartBugs Curated Negative Evaluation")
    lines.append("")
    lines.append("- Dataset: `datasets/smartbugs-curated/dataset`")
    lines.append("- Negative-sample definition: all categories except `reentrancy`.")
    lines.append("- Metric note: this subset is used to measure false positives for reentrancy detection.")
    if summary.get("bounded_ccr_cases"):
        lines.append(
            f"- Bounded CCR mode: enabled for {summary['bounded_ccr_cases']} cases; "
            f"{summary['bounded_ccr_truncated_cases']} reached a configured state/time limit."
        )
    lines.append("")
    lines.append("## Main Table")
    lines.append("")
    lines.append("| Cases | Analyzed | TN | FP | Failed | Timeout | FPR (Analyzed) | FPR (All) | Avg Runtime (s) | Findings |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        "| {total_cases} | {ok_cases} | {true_negative_cases} | {false_positive_cases} | "
        "{analysis_failed_cases} | {timeout_cases} | {fpr_analyzed} | {fpr_all} | "
        "{avg_runtime_seconds} | {total_findings} |".format(
            **{
                **summary,
                "fpr_analyzed": format_rate(summary["fpr_analyzed"]),
                "fpr_all": format_rate(summary["fpr_all"]),
                "avg_runtime_seconds": format_rate(summary["avg_runtime_seconds"]),
            }
        )
    )
    lines.append("")
    lines.append("## Finding Types")
    lines.append("")
    lines.append("| Classic | Cross-Contract | ROR |")
    lines.append("| ---: | ---: | ---: |")
    lines.append(
        f"| {summary['classic_reentrancy_findings']} | "
        f"{summary['cross_contract_reentrancy_findings']} | {summary['ror_findings']} |"
    )
    lines.append("")
    lines.append("## Category Breakdown")
    lines.append("")
    lines.append("| Category | Cases | Analyzed | TN | FP | Failed | Timeout | FPR (Analyzed) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for category, values in summary["by_category"].items():
        lines.append(
            f"| `{category}` | {values['cases']} | {values['analyzed']} | {values['true_negatives']} | "
            f"{values['false_positives']} | {values['failed']} | {values['timeout']} | "
            f"{format_rate(values['fpr_analyzed'])} |"
        )
    lines.append("")
    lines.append("## False Positive Cases")
    lines.append("")
    fp_records = [record for record in records if int(record["false_positive"])]
    if not fp_records:
        lines.append("No false positives were reported.")
    else:
        lines.append("| Case | Category | Findings | Types | Runtime (s) |")
        lines.append("| --- | --- | ---: | --- | ---: |")
        for record in fp_records:
            lines.append(
                f"| `{record['case_id']}` | `{record['category']}` | {record['total_vulnerabilities']} | "
                f"{record['vuln_types'] or 'None'} | {float(record['runtime_seconds']):.3f} |"
            )

    non_ok = [record for record in records if record["status"] != "ok"]
    if non_ok:
        lines.append("")
        lines.append("## Non-Analyzed Cases")
        lines.append("")
        lines.append("| Case | Category | Status | Error |")
        lines.append("| --- | --- | --- | --- |")
        for record in non_ok:
            error = (record.get("error") or "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{record['case_id']}` | `{record['category']}` | `{record['status']}` | {error} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex_table(path: Path, summary: dict[str, Any]) -> None:
    table = rf"""\begin{{table}}[t]
\centering
\caption{{False-positive results on the non-reentrancy categories of SmartBugs Curated.}}
\label{{tab:smartbugs-negative-results}}
\begin{{tabular}}{{lrrrrrrrr}}
\toprule
Dataset & Cases & Analyzed & TN & FP & Failed & Timeout & FPR$_{{analyzed}}$ & FPR$_{{all}}$ \\
\midrule
SmartBugs Neg. & {summary['total_cases']} & {summary['ok_cases']} & {summary['true_negative_cases']} & {summary['false_positive_cases']} & {summary['analysis_failed_cases']} & {summary['timeout_cases']} & {format_rate(summary['fpr_analyzed'])} & {format_rate(summary['fpr_all'])} \\
\bottomrule
\end{{tabular}}
\end{{table}}
"""
    path.write_text(table, encoding="utf-8")


def write_paper_text(path: Path, summary: dict[str, Any]) -> None:
    bounded_note = ""
    if summary.get("bounded_ccr_cases"):
        bounded_note = (
            f" A bounded CCR fallback was used for {summary['bounded_ccr_cases']} previously non-analyzed "
            f"contracts, with {summary['bounded_ccr_truncated_cases']} cases reaching the configured "
            "state/time limit; these fallback results are therefore reported as reduced-precision coverage."
        )
    text = (
        "For the negative-sample experiment, we used all non-reentrancy categories in SmartBugs Curated. "
        f"The tool successfully analyzed {summary['ok_cases']} out of {summary['total_cases']} contracts. "
        f"Among the analyzed contracts, {summary['true_negative_cases']} were correctly left unreported and "
        f"{summary['false_positive_cases']} produced at least one reentrancy-family warning, giving an analyzed-case "
        f"false-positive rate of {format_rate(summary['fpr_analyzed'])}. Counting compilation failures and timeouts "
        f"in the denominator, the end-to-end false-positive rate is {format_rate(summary['fpr_all'])}. "
        f"The reported false positives contain {summary['classic_reentrancy_findings']} classic reentrancy findings, "
        f"{summary['cross_contract_reentrancy_findings']} cross-contract findings, and {summary['ror_findings']} "
        f"read-only reentrancy findings.{bounded_note}\n"
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cases = collect_cases(
        dataset_dir=dataset_dir,
        excluded_categories=set(args.exclude_category or []),
        selected_categories=set(args.category) if args.category else None,
        selected_case_ids=set(args.selected_cases) if args.selected_cases else None,
        limit=args.limit,
    )
    if not cases:
        raise SystemExit(f"No negative Solidity files found under {dataset_dir}")

    print(f"Selected {len(cases)} SmartBugs negative cases.")
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(evaluate_case, case, args, output_dir): case for case in cases}
        for index, future in enumerate(as_completed(futures), start=1):
            case = futures[future]
            try:
                record = future.result()
            except Exception as exc:
                record = {
                    "case_id": case.case_id,
                    "category": case.category,
                    "input_path": display_path(case.contract_path),
                    "status": "script_failed",
                    "false_positive": 0,
                    "runtime_seconds": 0.0,
                    "report_dir": "",
                    "raw_log": "",
                    "error": str(exc),
                    "bounded_ccr": int(bool(args.bounded_ccr)),
                    "bounded_ccr_truncated": 0,
                    "total_vulnerabilities": 0,
                    "classic_reentrancy_count": 0,
                    "cross_contract_reentrancy_count": 0,
                    "ror_count": 0,
                    "high_severity": 0,
                    "medium_severity": 0,
                    "low_severity": 0,
                    "vuln_types": "",
                    "severities": "",
                }
            records.append(record)
            print(
                f"[{index}/{len(cases)}] {case.case_id} -> status={record['status']}, "
                f"fp={record['false_positive']}, findings={record['total_vulnerabilities']}"
            )

    records.sort(key=lambda record: (record["category"], record["case_id"]))
    summary = compute_summary(records)
    full_summary = {"summary": summary, "records": records}

    (output_dir / "summary.json").write_text(json.dumps(full_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_predictions_csv(output_dir / "smartbugs_negative_predictions.csv", records)
    write_summary_markdown(output_dir / "paper_results.md", summary, records)
    write_latex_table(output_dir / "paper_table.tex", summary)
    write_paper_text(output_dir / "paper_paragraph.md", summary)

    print("\nArtifacts written:")
    print(f"- Summary JSON: {output_dir / 'summary.json'}")
    print(f"- Predictions CSV: {output_dir / 'smartbugs_negative_predictions.csv'}")
    print(f"- Paper results MD: {output_dir / 'paper_results.md'}")
    print(f"- LaTeX table: {output_dir / 'paper_table.tex'}")
    print(f"- Paper paragraph: {output_dir / 'paper_paragraph.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
