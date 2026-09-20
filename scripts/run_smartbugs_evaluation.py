#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_DIR = ROOT / "contracts" / "smartbugs"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "smartbugs_eval"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"
DEFAULT_ANNOTATION_FILE = ROOT / "datasets" / "smartbugs-curated" / "vulnerabilities.json"


@dataclass(frozen=True)
class SmartBugsCase:
    case_id: str
    contract_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Reentrancy Guardian on contracts/smartbugs and generate paper-ready "
            "tables for the positive SmartBugs reentrancy cases."
        )
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help="Directory containing SmartBugs case folders.",
    )
    parser.add_argument(
        "--dataset-label",
        help="Human-readable dataset label used in generated paper tables.",
    )
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--annotation-file",
        default=str(DEFAULT_ANNOTATION_FILE),
        help="SmartBugs annotation JSON used to add benchmark line-alignment metadata.",
    )
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
        "--workers",
        type=int,
        default=max(1, min(2, os.cpu_count() or 1)),
        help="Number of parallel contract analyses.",
    )
    parser.add_argument("--force", action="store_true", help="Re-run cases even if cached results exist.")
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run only this case id.")
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


def collect_cases(input_dir: Path, selected_cases: Optional[list[str]]) -> list[SmartBugsCase]:
    wanted = set(selected_cases or [])
    cases: list[SmartBugsCase] = []

    for contract_path in sorted(input_dir.rglob("*.sol"), key=lambda path: str(path).lower()):
        try:
            rel = contract_path.relative_to(input_dir)
        except ValueError:
            rel = contract_path
        case_id = rel.parts[0] if len(rel.parts) > 1 else contract_path.stem
        if wanted and case_id not in wanted:
            continue
        cases.append(SmartBugsCase(case_id=case_id, contract_path=contract_path))

    missing = sorted(wanted - {case.case_id for case in cases})
    if missing:
        raise SystemExit(f"Unknown SmartBugs case ids: {', '.join(missing)}")

    return cases


def build_command(case: SmartBugsCase, report_dir: Path, args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        str(MAIN_SCRIPT),
        str(case.contract_path),
        "--json",
        "--csv",
        "-o",
        str(report_dir),
        "--timeout",
        str(args.analysis_timeout),
    ]


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


def load_reentrancy_annotations(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}

    annotations: dict[str, dict[str, Any]] = {}
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data:
        raw_path = str(item.get("path") or "").replace("\\", "/")
        if not raw_path.endswith(".sol"):
            continue

        lines: set[int] = set()
        categories: set[str] = set()
        for vulnerability in item.get("vulnerabilities") or []:
            category = str(vulnerability.get("category") or "")
            if category != "reentrancy":
                continue
            categories.add(category)
            for line in vulnerability.get("lines") or []:
                try:
                    lines.add(int(line))
                except (TypeError, ValueError):
                    continue

        if not lines:
            continue

        case_id = Path(raw_path).stem
        annotations[case_id] = {
            "name": item.get("name") or f"{case_id}.sol",
            "path": raw_path,
            "categories": sorted(categories),
            "annotated_lines": sorted(lines),
        }
    return annotations


def reported_locations(report: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for vulnerability in report.get("vulnerabilities") or []:
        external_call = vulnerability.get("external_call") or {}
        line = external_call.get("line")
        try:
            line_number = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_number = None
        locations.append(
            {
                "line": line_number,
                "function": external_call.get("function") or vulnerability.get("source_function"),
                "source_function": vulnerability.get("source_function"),
                "target_function": vulnerability.get("target_function"),
                "vuln_type": vulnerability.get("vuln_type"),
                "expression": external_call.get("expression") or "",
            }
        )
    return locations


def build_benchmark_alignment(
    record: dict[str, Any],
    annotation: Optional[dict[str, Any]],
    report: dict[str, Any],
) -> dict[str, Any]:
    locations = reported_locations(report)
    reported_lines = sorted({loc["line"] for loc in locations if loc.get("line")})

    if not annotation:
        return {
            "annotated": False,
            "annotation_path": "",
            "annotated_lines": [],
            "reported_lines": reported_lines,
            "matched_lines": [],
            "missing_annotated_lines": [],
            "extra_reported_lines": reported_lines,
            "exact_line_match": False,
            "semantic_match": bool(int(record.get("detected") or 0)),
            "alignment_type": "unannotated",
            "alignment_note": "No SmartBugs line annotation was found for this case.",
            "reported_locations": locations,
        }

    annotated_lines = list(annotation.get("annotated_lines") or [])
    matched_lines = sorted(set(annotated_lines) & set(reported_lines))
    missing_lines = sorted(set(annotated_lines) - set(reported_lines))
    extra_lines = sorted(set(reported_lines) - set(annotated_lines))
    detected = bool(int(record.get("detected") or 0))

    if matched_lines and not missing_lines and not extra_lines:
        alignment_type = "exact"
        note = "Reported external-call location exactly matches the benchmark annotated line set."
    elif matched_lines:
        alignment_type = "partial"
        note = "At least one benchmark annotated line is reported; extra or missing reported locations remain."
    elif detected:
        alignment_type = "semantic"
        note = (
            "The sample is detected, but the detector reports the concrete external-call site "
            "or call-chain location instead of the benchmark annotated line."
        )
    else:
        alignment_type = "missed"
        note = "No finding was reported for this annotated reentrancy sample."

    return {
        "annotated": True,
        "annotation_path": annotation.get("path") or "",
        "annotated_lines": annotated_lines,
        "reported_lines": reported_lines,
        "matched_lines": matched_lines,
        "missing_annotated_lines": missing_lines,
        "extra_reported_lines": extra_lines,
        "exact_line_match": bool(matched_lines),
        "semantic_match": detected,
        "alignment_type": alignment_type,
        "alignment_note": note,
        "reported_locations": locations,
    }


def apply_benchmark_alignment(
    records: list[dict[str, Any]],
    annotations: dict[str, dict[str, Any]],
    output_dir: Path,
) -> None:
    for record in records:
        report_dir = output_dir / "reports" / str(record["case_id"])
        report = load_report(report_dir) if record.get("status") == "ok" else {}
        alignment = build_benchmark_alignment(record, annotations.get(str(record["case_id"])), report)
        record["benchmark_alignment"] = alignment
        record["annotated_lines"] = "; ".join(str(line) for line in alignment["annotated_lines"])
        record["reported_lines"] = "; ".join(str(line) for line in alignment["reported_lines"])
        record["matched_lines"] = "; ".join(str(line) for line in alignment["matched_lines"])
        record["missing_annotated_lines"] = "; ".join(
            str(line) for line in alignment["missing_annotated_lines"]
        )
        record["extra_reported_lines"] = "; ".join(str(line) for line in alignment["extra_reported_lines"])
        record["exact_line_match"] = int(bool(alignment["exact_line_match"]))
        record["semantic_line_match"] = int(bool(alignment["semantic_match"]))
        record["alignment_type"] = alignment["alignment_type"]
        record["alignment_note"] = alignment["alignment_note"]

        record_path = output_dir / "records" / f"{record['case_id']}.json"
        if record_path.parent.exists():
            record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")


def evaluate_case(case: SmartBugsCase, args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
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
    cmd = build_command(case, report_dir, args)
    status = "ok"
    error: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=args.process_timeout,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        if completed.returncode != 0:
            status = "analysis_failed"
            error = trim_text((completed.stdout or "") + "\n" + (completed.stderr or ""))
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout = exc.stdout if isinstance(exc.stdout, str) else None
        stderr = exc.stderr if isinstance(exc.stderr, str) else None
        error = f"Process timeout after {args.process_timeout}s"

    runtime_seconds = perf_counter() - started
    report = load_report(report_dir) if status == "ok" else {}
    report_summary = summarize_report(report)
    detected = status == "ok" and report_summary["total_vulnerabilities"] > 0

    record = {
        "case_id": case.case_id,
        "input_path": display_path(case.contract_path),
        "status": status,
        "detected": int(detected),
        "runtime_seconds": runtime_seconds,
        "report_dir": display_path(report_dir),
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
        "input_path",
        "status",
        "detected",
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
        "annotated_lines",
        "reported_lines",
        "matched_lines",
        "missing_annotated_lines",
        "extra_reported_lines",
        "exact_line_match",
        "semantic_line_match",
        "alignment_type",
        "alignment_note",
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
    detected_cases = sum(int(record["detected"]) for record in records)
    missed_cases = sum(1 for record in records if record["status"] == "ok" and not int(record["detected"]))
    failed_cases = sum(1 for record in records if record["status"] == "analysis_failed")
    timeout_cases = sum(1 for record in records if record["status"] == "timeout")
    total_findings = sum(int(record["total_vulnerabilities"]) for record in records)
    annotated_cases = sum(1 for record in records if record.get("benchmark_alignment", {}).get("annotated"))
    exact_line_matches = sum(int(record.get("exact_line_match") or 0) for record in records)
    semantic_line_matches = sum(int(record.get("semantic_line_match") or 0) for record in records)
    semantic_only_matches = sum(1 for record in records if record.get("alignment_type") == "semantic")
    partial_line_matches = sum(1 for record in records if record.get("alignment_type") == "partial")
    exact_alignment_cases = sum(1 for record in records if record.get("alignment_type") == "exact")

    analyzable_detection_rate = detected_cases / ok_cases if ok_cases else None
    end_to_end_detection_rate = detected_cases / total_cases if total_cases else None
    avg_runtime = (
        sum(float(record["runtime_seconds"]) for record in records if record["status"] == "ok") / ok_cases
        if ok_cases
        else None
    )

    return {
        "total_cases": total_cases,
        "ok_cases": ok_cases,
        "detected_cases": detected_cases,
        "missed_cases": missed_cases,
        "analysis_failed_cases": failed_cases,
        "timeout_cases": timeout_cases,
        "total_findings": total_findings,
        "classic_reentrancy_findings": sum(int(record["classic_reentrancy_count"]) for record in records),
        "cross_contract_reentrancy_findings": sum(int(record["cross_contract_reentrancy_count"]) for record in records),
        "ror_findings": sum(int(record["ror_count"]) for record in records),
        "analyzable_detection_rate": analyzable_detection_rate,
        "end_to_end_detection_rate": end_to_end_detection_rate,
        "avg_runtime_seconds": avg_runtime,
        "annotated_cases": annotated_cases,
        "exact_line_match_cases": exact_line_matches,
        "semantic_line_match_cases": semantic_line_matches,
        "semantic_only_match_cases": semantic_only_matches,
        "partial_line_match_cases": partial_line_matches,
        "exact_alignment_cases": exact_alignment_cases,
        "exact_line_match_rate_detected": exact_line_matches / detected_cases if detected_cases else None,
        "semantic_line_match_rate_detected": semantic_line_matches / detected_cases if detected_cases else None,
        "status_summary": {
            status: sum(1 for record in records if record["status"] == status)
            for status in sorted({str(record["status"]) for record in records})
        },
    }


def format_rate(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def write_summary_markdown(
    path: Path,
    summary: dict[str, Any],
    records: list[dict[str, Any]],
    dataset_label: str,
) -> None:
    lines: list[str] = []
    lines.append("# Reentrancy Positive Evaluation")
    lines.append("")
    lines.append(f"- Dataset: `{dataset_label}`")
    lines.append("- Ground truth assumption: all cases in this directory are treated as reentrancy-positive samples.")
    lines.append("- Metric note: this positive-only subset supports detection rate/recall, not precision.")
    if summary.get("annotated_cases"):
        lines.append(
            "- Location note: the detector reports the concrete external-call site as the primary location; "
            "benchmark alignment records SmartBugs annotated lines separately."
        )
    lines.append("")
    lines.append("## Main Table")
    lines.append("")
    lines.append("| Cases | Analyzed | Detected | Missed | Failed | Timeout | Detection Rate (Analyzed) | Detection Rate (All) | Avg Runtime (s) | Findings |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        "| {total_cases} | {ok_cases} | {detected_cases} | {missed_cases} | {analysis_failed_cases} | "
        "{timeout_cases} | {analyzable_detection_rate} | {end_to_end_detection_rate} | {avg_runtime_seconds} | "
        "{total_findings} |".format(
            **{
                **summary,
                "analyzable_detection_rate": format_rate(summary["analyzable_detection_rate"]),
                "end_to_end_detection_rate": format_rate(summary["end_to_end_detection_rate"]),
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
    if summary.get("annotated_cases"):
        lines.append("")
        lines.append("## Benchmark Alignment")
        lines.append("")
        lines.append("| Annotated Cases | Annotated-Line Hit | Partial Line Match | Semantic-Only Match | Semantic Match | Line-Hit Rate (Detected) |")
        lines.append("| ---: | ---: | ---: | ---: | ---: | ---: |")
        lines.append(
            f"| {summary['annotated_cases']} | {summary['exact_line_match_cases']} | "
            f"{summary['partial_line_match_cases']} | {summary['semantic_only_match_cases']} | "
            f"{summary['semantic_line_match_cases']} | {format_rate(summary['exact_line_match_rate_detected'])} |"
        )
    lines.append("")
    lines.append("## Per-Case Results")
    lines.append("")
    lines.append("| Case | Status | Detected | Findings | Types | Alignment | Annotated Lines | Reported Lines | Runtime (s) |")
    lines.append("| --- | --- | ---: | ---: | --- | --- | --- | --- | ---: |")
    for record in records:
        lines.append(
            f"| `{record['case_id']}` | `{record['status']}` | {record['detected']} | "
            f"{record['total_vulnerabilities']} | {record['vuln_types'] or 'None'} | "
            f"`{record.get('alignment_type') or 'n/a'}` | {record.get('annotated_lines') or ''} | "
            f"{record.get('reported_lines') or ''} | "
            f"{float(record['runtime_seconds']):.3f} |"
        )

    failed = [record for record in records if record["status"] != "ok"]
    if failed:
        lines.append("")
        lines.append("## Non-Analyzed Cases")
        lines.append("")
        lines.append("| Case | Status | Error |")
        lines.append("| --- | --- | --- |")
        for record in failed:
            error = (record.get("error") or "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{record['case_id']}` | `{record['status']}` | {error} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_benchmark_alignment_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "status",
        "detected",
        "annotated_lines",
        "reported_lines",
        "matched_lines",
        "missing_annotated_lines",
        "extra_reported_lines",
        "exact_line_match",
        "semantic_line_match",
        "alignment_type",
        "alignment_note",
        "input_path",
        "report_dir",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field) for field in fieldnames})


def write_benchmark_alignment_markdown(
    path: Path,
    summary: dict[str, Any],
    records: list[dict[str, Any]],
) -> None:
    lines: list[str] = []
    lines.append("# SmartBugs Benchmark Alignment")
    lines.append("")
    lines.append("- Primary detector location: concrete external-call site.")
    lines.append("- Benchmark location: SmartBugs annotated reentrancy line from `vulnerabilities.json`.")
    lines.append("- `semantic` means the sample is detected, but reported lines differ from benchmark lines.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Cases | Detected | Annotated-Line Hit | Partial | Semantic-Only | Missed | Line-Hit Rate (Detected) | Semantic Rate (Detected) |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        f"| {summary['annotated_cases']} | {summary['detected_cases']} | "
        f"{summary['exact_line_match_cases']} | {summary['partial_line_match_cases']} | "
        f"{summary['semantic_only_match_cases']} | {summary['missed_cases']} | "
        f"{format_rate(summary['exact_line_match_rate_detected'])} | "
        f"{format_rate(summary['semantic_line_match_rate_detected'])} |"
    )
    lines.append("")
    lines.append("## Per-Case Alignment")
    lines.append("")
    lines.append("| Case | Alignment | Annotated | Reported | Matched | Missing | Extra | Note |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for record in records:
        note = (record.get("alignment_note") or "").replace("|", "\\|")
        lines.append(
            f"| `{record['case_id']}` | `{record.get('alignment_type') or 'n/a'}` | "
            f"{record.get('annotated_lines') or ''} | {record.get('reported_lines') or ''} | "
            f"{record.get('matched_lines') or ''} | {record.get('missing_annotated_lines') or ''} | "
            f"{record.get('extra_reported_lines') or ''} | {note} |"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex_table(path: Path, summary: dict[str, Any], dataset_label: str) -> None:
    row_label = dataset_label.replace("\\", "/")
    table = rf"""\begin{{table}}[t]
\centering
\caption{{Detection results on the reentrancy-positive contract set.}}
\label{{tab:positive-reentrancy-results}}
\begin{{tabular}}{{lrrrrrrrr}}
\toprule
Dataset & Cases & Analyzed & Detected & Missed & Failed & Timeout & Recall$_{{analyzed}}$ & Recall$_{{all}}$ \\
\midrule
{row_label} & {summary['total_cases']} & {summary['ok_cases']} & {summary['detected_cases']} & {summary['missed_cases']} & {summary['analysis_failed_cases']} & {summary['timeout_cases']} & {format_rate(summary['analyzable_detection_rate'])} & {format_rate(summary['end_to_end_detection_rate'])} \\
\bottomrule
\end{{tabular}}
\end{{table}}
"""
    path.write_text(table, encoding="utf-8")


def write_paper_text(path: Path, summary: dict[str, Any], dataset_label: str) -> None:
    text = (
        f"On the {dataset_label} reentrancy-positive subset, Reentrancy Guardian successfully analyzed "
        f"{summary['ok_cases']} out of {summary['total_cases']} contracts. Among the successfully "
        f"analyzed contracts, it reported at least one reentrancy-family finding for "
        f"{summary['detected_cases']} cases, yielding an analyzed-case detection rate of "
        f"{format_rate(summary['analyzable_detection_rate'])}. When compilation failures and timeouts "
        f"are counted as non-detections, the end-to-end detection rate is "
        f"{format_rate(summary['end_to_end_detection_rate'])}. The tool reported "
        f"{summary['total_findings']} findings in total, including "
        f"{summary['classic_reentrancy_findings']} classic reentrancy findings, "
        f"{summary['cross_contract_reentrancy_findings']} cross-contract reentrancy findings, and "
        f"{summary['ror_findings']} read-only reentrancy findings.\n"
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_label = args.dataset_label or display_path(input_dir)
    annotations = load_reentrancy_annotations(Path(args.annotation_file))

    cases = collect_cases(input_dir, args.selected_cases)
    if not cases:
        raise SystemExit(f"No Solidity files found under {input_dir}")

    print(f"Selected {len(cases)} SmartBugs cases.")
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
                    "input_path": display_path(case.contract_path),
                    "status": "script_failed",
                    "detected": 0,
                    "runtime_seconds": 0.0,
                    "report_dir": "",
                    "error": str(exc),
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
                f"[{index}/{len(cases)}] {case.case_id} -> "
                f"status={record['status']}, detected={record['detected']}, "
                f"findings={record['total_vulnerabilities']}"
            )

    records.sort(key=lambda record: record["case_id"])
    apply_benchmark_alignment(records, annotations, output_dir)
    summary = compute_summary(records)
    full_summary = {"summary": summary, "records": records}

    (output_dir / "summary.json").write_text(json.dumps(full_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_predictions_csv(output_dir / "smartbugs_predictions.csv", records)
    write_benchmark_alignment_csv(output_dir / "benchmark_alignment.csv", records)
    write_benchmark_alignment_markdown(output_dir / "benchmark_alignment.md", summary, records)
    write_summary_markdown(output_dir / "paper_results.md", summary, records, dataset_label)
    write_latex_table(output_dir / "paper_table.tex", summary, dataset_label)
    write_paper_text(output_dir / "paper_paragraph.md", summary, dataset_label)

    print("\nArtifacts written:")
    print(f"- Summary JSON: {output_dir / 'summary.json'}")
    print(f"- Predictions CSV: {output_dir / 'smartbugs_predictions.csv'}")
    print(f"- Benchmark alignment CSV: {output_dir / 'benchmark_alignment.csv'}")
    print(f"- Benchmark alignment MD: {output_dir / 'benchmark_alignment.md'}")
    print(f"- Paper results MD: {output_dir / 'paper_results.md'}")
    print(f"- LaTeX table: {output_dir / 'paper_table.tex'}")
    print(f"- Paper paragraph: {output_dir / 'paper_paragraph.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
