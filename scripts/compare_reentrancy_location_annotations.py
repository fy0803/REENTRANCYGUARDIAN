#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT_DIR = ROOT / "datasets" / "ReentrancyStudy-Data" / "reentrant_contracts"
DEFAULT_RESULT_DIR = ROOT / "results" / "reentrant_contracts_eval"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "reentrant_contracts_location_check"


FUNCTION_RE = re.compile(r"\bfunction\s*([A-Za-z_][A-Za-z0-9_]*)?\s*\(")
CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
YES_RE = re.compile(r"<yes>\s*reentrancy", re.IGNORECASE)
NO_RE = re.compile(r"<no>\s*reentrancy", re.IGNORECASE)


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class Label:
    line: int
    function: str
    function_start: int
    function_end: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare Reentrancy Guardian reports against <yes> Reentrancy annotations "
            "in ReentrancyStudy-Data/reentrant_contracts."
        )
    )
    parser.add_argument("--contracts-dir", default=str(DEFAULT_CONTRACT_DIR), help="Annotated contract directory.")
    parser.add_argument("--result-dir", default=str(DEFAULT_RESULT_DIR), help="Evaluation result directory.")
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    return parser.parse_args()


def normalize_function(name: str) -> str:
    return (name or "fallback").strip().lower()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def parse_function_spans(lines: list[str]) -> list[FunctionSpan]:
    spans: list[FunctionSpan] = []
    index = 0
    while index < len(lines):
        match = FUNCTION_RE.search(lines[index])
        if not match:
            index += 1
            continue

        name = match.group(1) or "fallback"
        start_line = index + 1
        depth = 0
        seen_body = False
        end_line = start_line
        cursor = index
        while cursor < len(lines):
            text = lines[cursor]
            if not seen_body and ";" in text and "{" not in text:
                end_line = cursor + 1
                break
            depth += text.count("{")
            if "{" in text:
                seen_body = True
            depth -= text.count("}")
            end_line = cursor + 1
            if seen_body and depth <= 0:
                break
            cursor += 1

        spans.append(FunctionSpan(name=name, start_line=start_line, end_line=end_line))
        index = max(cursor + 1, index + 1)
    return spans


def find_span_for_line(spans: list[FunctionSpan], line: int) -> Optional[FunctionSpan]:
    for span in spans:
        if span.start_line <= line <= span.end_line:
            return span
    return None


def find_next_function_span(spans: list[FunctionSpan], line: int) -> Optional[FunctionSpan]:
    candidates = [span for span in spans if span.start_line >= line]
    return min(candidates, key=lambda span: span.start_line) if candidates else None


def extract_labels(path: Path) -> list[Label]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    spans = parse_function_spans(lines)
    labels: list[Label] = []

    for index, line in enumerate(lines, start=1):
        if not YES_RE.search(line):
            continue

        span = find_span_for_line(spans, index)
        if span is None:
            span = find_next_function_span(spans, index)
        if span is None:
            continue
        labels.append(
            Label(
                line=index,
                function=span.name,
                function_start=span.start_line,
                function_end=span.end_line,
            )
        )
    return labels


def load_report(result_dir: Path, case_id: str) -> dict[str, Any]:
    report_path = result_dir / "reports" / case_id / "vulnerabilities.json"
    if not report_path.exists():
        return {}
    return json.loads(report_path.read_text(encoding="utf-8"))


def load_prediction(result_dir: Path) -> dict[str, dict[str, str]]:
    predictions_path = result_dir / "smartbugs_predictions.csv"
    if not predictions_path.exists():
        return {}
    with predictions_path.open("r", encoding="utf-8", newline="") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def summarize_case(path: Path, result_dir: Path, prediction: dict[str, str]) -> dict[str, Any]:
    case_id = path.stem
    labels = extract_labels(path)
    report = load_report(result_dir, case_id)
    vulnerabilities = report.get("vulnerabilities") or []
    normalized_label_functions = {normalize_function(label.function) for label in labels}

    reported_functions = [
        str(item.get("source_function") or "")
        for item in vulnerabilities
        if item.get("source_function")
    ]
    external_call_lines = [
        int((item.get("external_call") or {}).get("line") or 0)
        for item in vulnerabilities
        if (item.get("external_call") or {}).get("line")
    ]

    matched_vulnerability: Optional[dict[str, Any]] = None
    for item in vulnerabilities:
        if normalize_function(str(item.get("source_function") or "")) in normalized_label_functions:
            matched_vulnerability = item
            break

    matched_line = 0
    line_in_labeled_function = False
    for line in external_call_lines:
        for label in labels:
            if line and label.function_start <= line <= label.function_end:
                line_in_labeled_function = True
                matched_line = line
                break
        if line_in_labeled_function:
            break

    if matched_vulnerability:
        function_matched_line = int((matched_vulnerability.get("external_call") or {}).get("line") or 0)
        matched_function = normalize_function(str(matched_vulnerability.get("source_function") or ""))
        for label in labels:
            if normalize_function(label.function) != matched_function:
                continue
            if function_matched_line and label.function_start <= function_matched_line <= label.function_end:
                line_in_labeled_function = True
                matched_line = function_matched_line
                break

    detected = int(prediction.get("detected") or 0)
    function_match = bool(matched_vulnerability)
    status = prediction.get("status") or ("ok" if report else "missing_report")
    label_functions = "; ".join(label.function for label in labels)
    label_lines = "; ".join(str(label.line) for label in labels)
    label_spans = "; ".join(f"{label.function}:{label.function_start}-{label.function_end}" for label in labels)

    return {
        "case_id": case_id,
        "status": status,
        "detected": detected,
        "label_functions": label_functions,
        "label_lines": label_lines,
        "label_spans": label_spans,
        "reported_functions": "; ".join(reported_functions),
        "external_call_lines": "; ".join(str(line) for line in external_call_lines),
        "function_location_match": int(function_match),
        "line_in_labeled_function": int(line_in_labeled_function),
        "matched_external_call_line": matched_line or "",
        "num_findings": len(vulnerabilities),
        "input_path": display_path(path),
    }


def compute_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    detected = sum(int(record["detected"]) for record in records)
    missed = sum(1 for record in records if not int(record["detected"]))
    function_matches = sum(int(record["function_location_match"]) for record in records)
    line_matches = sum(int(record["line_in_labeled_function"]) for record in records)
    return {
        "total_cases": total,
        "detected_cases": detected,
        "missed_cases": missed,
        "function_location_matches": function_matches,
        "line_in_labeled_function_matches": line_matches,
        "function_location_accuracy_all": function_matches / total if total else None,
        "function_location_accuracy_detected": function_matches / detected if detected else None,
        "line_location_accuracy_all": line_matches / total if total else None,
        "line_location_accuracy_detected": line_matches / detected if detected else None,
    }


def format_rate(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "status",
        "detected",
        "label_functions",
        "label_lines",
        "label_spans",
        "reported_functions",
        "external_call_lines",
        "function_location_match",
        "line_in_labeled_function",
        "matched_external_call_line",
        "num_findings",
        "input_path",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field) for field in fieldnames})


def write_markdown(path: Path, summary: dict[str, Any], records: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    lines.append("# Reentrancy Location Check")
    lines.append("")
    lines.append("- Ground truth: `<yes> Reentrancy` annotations in `datasets/ReentrancyStudy-Data/reentrant_contracts`.")
    lines.append("- Granularity: source-function match plus external-call line inside the annotated function body.")
    lines.append("- Caveat: the dataset does not provide exact vulnerable line ground truth in `reentrancy_information.csv`.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Cases | Detected | Missed | Source Function Matches | Function Acc. (Detected) | External Call Line Matches | Line Acc. (Detected) |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        f"| {summary['total_cases']} | {summary['detected_cases']} | {summary['missed_cases']} | "
        f"{summary['function_location_matches']} | {format_rate(summary['function_location_accuracy_detected'])} | "
        f"{summary['line_in_labeled_function_matches']} | {format_rate(summary['line_location_accuracy_detected'])} |"
    )

    missed = [record for record in records if not int(record["detected"])]
    mismatched = [
        record
        for record in records
        if int(record["detected"]) and not int(record["function_location_match"])
    ]

    lines.append("")
    lines.append("## Missed Cases")
    lines.append("")
    if not missed:
        lines.append("No missed cases.")
    else:
        lines.append("| Case | Label Function | Label Line |")
        lines.append("| --- | --- | ---: |")
        for record in missed:
            lines.append(f"| `{record['case_id']}` | `{record['label_functions']}` | {record['label_lines']} |")

    lines.append("")
    lines.append("## Function Mismatches")
    lines.append("")
    if not mismatched:
        lines.append("No function-level mismatches among detected cases.")
    else:
        lines.append("| Case | Label Function | Reported Functions | External Call Lines |")
        lines.append("| --- | --- | --- | --- |")
        for record in mismatched:
            lines.append(
                f"| `{record['case_id']}` | `{record['label_functions']}` | "
                f"`{record['reported_functions']}` | {record['external_call_lines']} |"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    contracts_dir = Path(args.contracts_dir)
    result_dir = Path(args.result_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    predictions = load_prediction(result_dir)
    records = [
        summarize_case(path, result_dir, predictions.get(path.stem, {}))
        for path in sorted(contracts_dir.glob("*.sol"), key=lambda item: item.name.lower())
    ]
    summary = compute_summary(records)

    (output_dir / "summary.json").write_text(
        json.dumps({"summary": summary, "records": records}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_csv(output_dir / "location_matches.csv", records)
    write_markdown(output_dir / "location_check.md", summary, records)

    print(f"Compared {summary['total_cases']} annotated reentrant contracts.")
    print(f"- Function matches among detected cases: {summary['function_location_matches']}/{summary['detected_cases']}")
    print(f"- Line-in-function matches among detected cases: {summary['line_in_labeled_function_matches']}/{summary['detected_cases']}")
    print(f"- Summary: {output_dir / 'summary.json'}")
    print(f"- CSV: {output_dir / 'location_matches.csv'}")
    print(f"- Markdown: {output_dir / 'location_check.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
