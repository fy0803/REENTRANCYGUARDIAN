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
from typing import Any, Iterable, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_CSV = ROOT / "datasets" / "ReentrancyStudy-Data" / "reentrancy_information.csv"
DEFAULT_CONTRACT_DIR = ROOT / "datasets" / "ReentrancyStudy-Data" / "deduplicated_smart_contracts"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "quantitative_eval"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"
OUR_TOOL = "reentrancy_guardian"
BASELINE_TOOLS = ["oyente", "mythril", "securify1", "securify2", "smartian", "sailfish"]


@dataclass(frozen=True)
class DatasetSample:
    address: str
    label: int
    contract_path: Path
    raw_row: dict[str, str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Reentrancy Guardian on ReentrancyStudy-Data and generate the main quantitative "
            "results table alongside baseline comparisons."
        )
    )
    parser.add_argument("--dataset-csv", default=str(DEFAULT_DATASET_CSV), help="Path to reentrancy_information.csv.")
    parser.add_argument(
        "--contracts-dir",
        default=str(DEFAULT_CONTRACT_DIR),
        help="Directory containing deduplicated Solidity contracts named by address.",
    )
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--mode",
        choices=("full", "ccr", "ror"),
        default="full",
        help="Run the full detector, CCR-only mode, or ROR-only mode.",
    )
    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=300,
        help="Seconds passed to Reentrancy Guardian's internal path validator timeout flag.",
    )
    parser.add_argument(
        "--process-timeout",
        type=int,
        default=600,
        help="Hard timeout in seconds for each subprocess invocation.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(4, os.cpu_count() or 1)),
        help="Number of concurrent subprocess workers.",
    )
    parser.add_argument("--limit", type=int, help="Maximum number of labelled contracts to evaluate.")
    parser.add_argument("--positives-limit", type=int, help="Maximum number of positive samples to evaluate.")
    parser.add_argument("--negatives-limit", type=int, help="Maximum number of negative samples to evaluate.")
    parser.add_argument(
        "--sample-order",
        choices=("address", "positives_first", "interleave"),
        default="address",
        help="Order in which labelled samples are scheduled for evaluation.",
    )
    parser.add_argument(
        "--addresses-file",
        help="Optional text file with one contract address per line. Only these addresses are evaluated.",
    )
    parser.add_argument(
        "--report-mode",
        choices=("none", "positives", "all"),
        default="positives",
        help="Keep no reports, only positive reports, or every per-contract JSON report.",
    )
    parser.add_argument("--force", action="store_true", help="Re-run contracts even if cached predictions exist.")
    parser.add_argument("--skip-run", action="store_true", help="Skip detector execution and regenerate tables only.")
    parser.add_argument(
        "--no-precision-filter",
        action="store_true",
        help="Disable conservative false-positive suppression filters in Reentrancy Guardian.",
    )
    parser.add_argument(
        "--ablation-no-icfg-modeling",
        action="store_true",
        help="Run Reentrancy Guardian with the no-ICFG modeling ablation.",
    )
    return parser.parse_args()


def parse_binary_label(value: str | None) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if text == "1":
        return 1
    if text == "0":
        return 0
    return None


def load_address_filter(path: str | None) -> Optional[set[str]]:
    if not path:
        return None
    values = {
        line.strip().lower()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    return values or None


def load_samples(
    dataset_csv: Path,
    contracts_dir: Path,
    limit: Optional[int],
    positives_limit: Optional[int],
    negatives_limit: Optional[int],
    address_filter: Optional[set[str]],
    sample_order: str,
) -> list[DatasetSample]:
    positive_samples: list[DatasetSample] = []
    negative_samples: list[DatasetSample] = []

    with dataset_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = sorted(reader, key=lambda row: row["address"].lower())

    for row in rows:
        address = row["address"].strip().lower()
        if address_filter and address not in address_filter:
            continue

        label = parse_binary_label(row.get("true_positive"))
        if label is None:
            continue

        if label == 1 and positives_limit is not None and len(positive_samples) >= positives_limit:
            continue
        if label == 0 and negatives_limit is not None and len(negative_samples) >= negatives_limit:
            continue

        sample = DatasetSample(
            address=address,
            label=label,
            contract_path=contracts_dir / f"{address}.sol",
            raw_row=row,
        )
        if label == 1:
            positive_samples.append(sample)
        else:
            negative_samples.append(sample)

    samples = order_samples(positive_samples, negative_samples, sample_order)
    if limit is not None:
        samples = samples[:limit]
    return samples


def order_samples(
    positive_samples: list[DatasetSample],
    negative_samples: list[DatasetSample],
    sample_order: str,
) -> list[DatasetSample]:
    positives = sorted(positive_samples, key=lambda sample: sample.address)
    negatives = sorted(negative_samples, key=lambda sample: sample.address)

    if sample_order == "positives_first":
        return positives + negatives

    if sample_order == "interleave":
        ordered: list[DatasetSample] = []
        max_len = max(len(positives), len(negatives))
        for index in range(max_len):
            if index < len(positives):
                ordered.append(positives[index])
            if index < len(negatives):
                ordered.append(negatives[index])
        return ordered

    return sorted(positives + negatives, key=lambda sample: sample.address)


def load_existing_records(path: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            address = str(record["address"]).lower()
            records[address] = record
    return records


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def trim_error_text(text: Optional[str], limit: int = 2000) -> Optional[str]:
    if not text:
        return None
    compact = text.strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 15] + "\n...[truncated]"


def clean_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def move_or_replace(src: Path, dst: Path) -> None:
    clean_directory(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


def build_command(sample: DatasetSample, temp_output_dir: Path, args: argparse.Namespace) -> list[str]:
    cmd = [
        sys.executable,
        str(MAIN_SCRIPT),
        str(sample.contract_path),
        "--json",
        "-o",
        str(temp_output_dir),
        "--timeout",
        str(args.analysis_timeout),
    ]
    if args.mode == "ccr":
        cmd.append("--ccr-only")
    elif args.mode == "ror":
        cmd.append("--ror-only")
    if args.no_precision_filter:
        cmd.append("--no-precision-filter")
    if args.ablation_no_icfg_modeling:
        cmd.append("--ablation-no-icfg-modeling")
    return cmd


def evaluate_sample(sample: DatasetSample, args: argparse.Namespace, scratch_root: Path, reports_root: Path) -> dict[str, Any]:
    started = perf_counter()
    temp_output_dir = scratch_root / sample.address
    clean_directory(temp_output_dir)
    report_path = temp_output_dir / "vulnerabilities.json"
    final_report_dir = reports_root / sample.address

    if not sample.contract_path.exists():
        return {
            "address": sample.address,
            "label": sample.label,
            "prediction": None,
            "status": "missing_source",
            "runtime_seconds": round(perf_counter() - started, 6),
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "report_dir": None,
            "error": f"Missing source file: {sample.contract_path}",
        }

    cmd = build_command(sample, temp_output_dir, args)
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=args.process_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        clean_directory(temp_output_dir)
        return {
            "address": sample.address,
            "label": sample.label,
            "prediction": None,
            "status": "timeout",
            "runtime_seconds": round(perf_counter() - started, 6),
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "report_dir": None,
            "error": f"Process timeout after {args.process_timeout}s",
        }

    runtime_seconds = round(perf_counter() - started, 6)
    stdout_text = completed.stdout.strip()
    stderr_text = completed.stderr.strip()

    if not report_path.exists():
        clean_directory(temp_output_dir)
        return {
            "address": sample.address,
            "label": sample.label,
            "prediction": None,
            "status": "analysis_failed",
            "runtime_seconds": runtime_seconds,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "report_dir": None,
            "error": trim_error_text(stderr_text or stdout_text or f"Process exited with code {completed.returncode}"),
        }

    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        clean_directory(temp_output_dir)
        return {
            "address": sample.address,
            "label": sample.label,
            "prediction": None,
            "status": "invalid_report",
            "runtime_seconds": runtime_seconds,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "report_dir": None,
            "error": f"Invalid JSON report: {exc}",
        }

    summary = report_data.get("summary", {})
    total_findings = int(summary.get("total_vulnerabilities", 0))
    classic_findings = int(summary.get("classic_reentrancy_count", 0))
    cross_contract_findings = int(summary.get("cross_contract_reentrancy_count", 0))
    ror_findings = int(summary.get("ror_count", 0))
    prediction = 1 if total_findings > 0 else 0

    kept_report_dir: Optional[str] = None
    if args.report_mode == "all" or (args.report_mode == "positives" and prediction == 1):
        move_or_replace(temp_output_dir, final_report_dir)
        kept_report_dir = display_path(final_report_dir)
    else:
        clean_directory(temp_output_dir)

    return {
        "address": sample.address,
        "label": sample.label,
        "prediction": prediction,
        "status": "ok" if completed.returncode == 0 else "ok_with_warnings",
        "runtime_seconds": runtime_seconds,
        "total_findings": total_findings,
        "classic_findings": classic_findings,
        "cross_contract_findings": cross_contract_findings,
        "ror_findings": ror_findings,
        "report_dir": kept_report_dir,
        "error": trim_error_text(stderr_text),
    }


def write_predictions_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    fieldnames = [
        "address",
        "label",
        "prediction",
        "status",
        "runtime_seconds",
        "total_findings",
        "classic_findings",
        "cross_contract_findings",
        "ror_findings",
        "report_dir",
        "error",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name) for name in fieldnames})


def safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator == 0:
        return None
    return numerator / denominator


def compute_metrics(tool_name: str, rows: list[dict[str, Any]], total_labelled_rows: int) -> dict[str, Any]:
    evaluable = [row for row in rows if row.get("prediction") in (0, 1) and row.get("label") in (0, 1)]
    tp = sum(1 for row in evaluable if row["label"] == 1 and row["prediction"] == 1)
    fp = sum(1 for row in evaluable if row["label"] == 0 and row["prediction"] == 1)
    fn = sum(1 for row in evaluable if row["label"] == 1 and row["prediction"] == 0)
    tn = sum(1 for row in evaluable if row["label"] == 0 and row["prediction"] == 0)
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)

    runtime_values = [
        float(row["runtime_seconds"])
        for row in evaluable
        if tool_name == OUR_TOOL and row.get("runtime_seconds") is not None
    ]
    avg_runtime = safe_ratio(sum(runtime_values), len(runtime_values)) if runtime_values else None

    return {
        "tool": tool_name,
        "evaluated_rows": len(evaluable),
        "coverage": safe_ratio(len(evaluable), total_labelled_rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "avg_runtime_seconds": avg_runtime,
    }


def tool_rows(samples: list[dict[str, Any]], tool_name: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for sample in samples:
        result.append(
            {
                "label": sample["label"],
                "prediction": sample.get(tool_name),
                "runtime_seconds": sample.get("runtime_seconds") if tool_name == OUR_TOOL else None,
            }
        )
    return result


def write_metrics_csv(path: Path, metrics_rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "tool",
        "evaluated_rows",
        "coverage",
        "tp",
        "fp",
        "fn",
        "tn",
        "precision",
        "recall",
        "f1",
        "avg_runtime_seconds",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in metrics_rows:
            writer.writerow(row)


def format_float(value: Any, digits: int = 4) -> str:
    if value is None or value == "":
        return "N/A"
    return f"{float(value):.{digits}f}"


def render_markdown_summary(
    output_path: Path,
    dataset_summary: dict[str, Any],
    status_summary: dict[str, int],
    metrics_rows: list[dict[str, Any]],
    common_subset_rows: list[dict[str, Any]],
) -> None:
    lines: list[str] = []
    lines.append("# Quantitative Evaluation Summary")
    lines.append("")
    lines.append(f"- Mode: `{dataset_summary['mode']}`")
    lines.append(f"- Sample order: `{dataset_summary['sample_order']}`")
    lines.append(f"- Labelled contracts selected: {dataset_summary['labelled_rows']}")
    lines.append(f"- Positive labels: {dataset_summary['positive_rows']}")
    lines.append(f"- Negative labels: {dataset_summary['negative_rows']}")
    lines.append("")
    lines.append("## Reentrancy Guardian Status")
    lines.append("")
    for status, count in sorted(status_summary.items()):
        lines.append(f"- `{status}`: {count}")
    lines.append("")
    lines.append("## Main Results")
    lines.append("")
    lines.append("| Tool | Evaluated | Coverage | Precision | Recall | F1 | Avg Runtime (s) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in metrics_rows:
        lines.append(
            f"| `{row['tool']}` | {row['evaluated_rows']} | {format_float(row['coverage'])} | "
            f"{format_float(row['precision'])} | {format_float(row['recall'])} | {format_float(row['f1'])} | "
            f"{format_float(row['avg_runtime_seconds'])} |"
        )

    if common_subset_rows:
        lines.append("")
        lines.append("## Common-Subset Results")
        lines.append("")
        lines.append("| Tool | Evaluated | Precision | Recall | F1 | Avg Runtime (s) |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for row in common_subset_rows:
            lines.append(
                f"| `{row['tool']}` | {row['evaluated_rows']} | {format_float(row['precision'])} | "
                f"{format_float(row['recall'])} | {format_float(row['f1'])} | "
                f"{format_float(row['avg_runtime_seconds'])} |"
            )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def build_combined_rows(samples: list[DatasetSample], records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    combined: list[dict[str, Any]] = []
    for sample in samples:
        record = records.get(sample.address, {})
        row: dict[str, Any] = {
            "address": sample.address,
            "label": sample.label,
            OUR_TOOL: record.get("prediction"),
            "status": record.get("status"),
            "runtime_seconds": record.get("runtime_seconds"),
            "report_dir": record.get("report_dir"),
        }
        for tool in BASELINE_TOOLS:
            row[tool] = parse_binary_label(sample.raw_row.get(tool))
        combined.append(row)
    return combined


def summarize_status(records: dict[str, dict[str, Any]], selected_addresses: set[str]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for address in selected_addresses:
        status = str(records.get(address, {}).get("status", "not_run"))
        summary[status] = summary.get(status, 0) + 1
    return summary


def compute_common_subset_metrics(rows: list[dict[str, Any]], total_labelled_rows: int) -> tuple[list[dict[str, Any]], int]:
    tools = [OUR_TOOL] + BASELINE_TOOLS
    common_rows = [row for row in rows if all(row.get(tool) in (0, 1) for tool in tools)]
    metrics_rows = [
        compute_metrics(tool, tool_rows(common_rows, tool), total_labelled_rows=len(common_rows) or total_labelled_rows)
        for tool in tools
    ]
    return metrics_rows if common_rows else [], len(common_rows)


def write_summary_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    args = parse_args()
    dataset_csv = Path(args.dataset_csv)
    contracts_dir = Path(args.contracts_dir)
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    scratch_root = output_dir / "_tmp"
    reports_root = output_dir / "reports"
    predictions_jsonl = output_dir / "predictions.jsonl"
    predictions_csv = output_dir / "predictions.csv"
    main_results_csv = output_dir / "main_results.csv"
    main_results_common_csv = output_dir / "main_results_common_subset.csv"
    main_results_md = output_dir / "main_results.md"
    summary_json = output_dir / "summary.json"

    address_filter = load_address_filter(args.addresses_file)
    samples = load_samples(
        dataset_csv=dataset_csv,
        contracts_dir=contracts_dir,
        limit=args.limit,
        positives_limit=args.positives_limit,
        negatives_limit=args.negatives_limit,
        address_filter=address_filter,
        sample_order=args.sample_order,
    )
    if not samples:
        print("No labelled samples selected.")
        return 1

    existing_records = load_existing_records(predictions_jsonl)
    selected_addresses = {sample.address for sample in samples}

    if args.force and predictions_jsonl.exists() and not args.skip_run:
        predictions_jsonl.unlink()
        existing_records = {}

    to_run = [
        sample
        for sample in samples
        if not args.skip_run and (args.force or sample.address not in existing_records)
    ]

    if to_run:
        print(f"Selected {len(samples)} labelled contracts. Running {len(to_run)} new evaluations...")
        scratch_root.mkdir(parents=True, exist_ok=True)
        reports_root.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            futures = {
                executor.submit(evaluate_sample, sample, args, scratch_root, reports_root): sample.address
                for sample in to_run
            }
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                record = future.result()
                existing_records[record["address"]] = record
                append_jsonl(predictions_jsonl, record)
                completed += 1
                status = record["status"]
                prediction = record["prediction"]
                print(f"[{completed}/{total}] {record['address']} -> status={status}, prediction={prediction}")
    else:
        print(f"Selected {len(samples)} labelled contracts. Reusing cached predictions only.")

    ordered_records = [
        existing_records.get(
            sample.address,
            {
                "address": sample.address,
                "label": sample.label,
                "prediction": None,
                "status": "not_run",
                "runtime_seconds": None,
                "total_findings": None,
                "classic_findings": None,
                "cross_contract_findings": None,
                "ror_findings": None,
                "report_dir": None,
                "error": None,
            },
        )
        for sample in samples
    ]
    write_predictions_csv(predictions_csv, ordered_records)

    combined_rows = build_combined_rows(samples, existing_records)
    total_labelled_rows = len(combined_rows)
    positive_rows = sum(1 for row in combined_rows if row["label"] == 1)
    negative_rows = sum(1 for row in combined_rows if row["label"] == 0)

    metrics_rows = [
        compute_metrics(tool, tool_rows(combined_rows, tool), total_labelled_rows=total_labelled_rows)
        for tool in [OUR_TOOL] + BASELINE_TOOLS
    ]
    write_metrics_csv(main_results_csv, metrics_rows)

    common_subset_rows, common_subset_size = compute_common_subset_metrics(combined_rows, total_labelled_rows)
    if common_subset_rows:
        write_metrics_csv(main_results_common_csv, common_subset_rows)

    status_summary = summarize_status(existing_records, selected_addresses)
    dataset_summary = {
        "mode": args.mode,
        "ablation_no_icfg_modeling": bool(args.ablation_no_icfg_modeling),
        "sample_order": args.sample_order,
        "labelled_rows": total_labelled_rows,
        "positive_rows": positive_rows,
        "negative_rows": negative_rows,
        "common_subset_rows": common_subset_size,
        "predictions_jsonl": display_path(predictions_jsonl),
        "predictions_csv": display_path(predictions_csv),
        "main_results_csv": display_path(main_results_csv),
        "main_results_md": display_path(main_results_md),
        "main_results_common_subset_csv": (display_path(main_results_common_csv) if common_subset_rows else None),
    }

    render_markdown_summary(
        output_path=main_results_md,
        dataset_summary=dataset_summary,
        status_summary=status_summary,
        metrics_rows=metrics_rows,
        common_subset_rows=common_subset_rows,
    )

    summary_payload = {
        "dataset_summary": dataset_summary,
        "status_summary": status_summary,
        "main_results": metrics_rows,
        "common_subset_results": common_subset_rows,
    }
    write_summary_json(summary_json, summary_payload)

    print("\nArtifacts written:")
    print(f"- Predictions JSONL: {predictions_jsonl}")
    print(f"- Predictions CSV:   {predictions_csv}")
    print(f"- Main results CSV:  {main_results_csv}")
    print(f"- Main results MD:   {main_results_md}")
    if common_subset_rows:
        print(f"- Common subset CSV: {main_results_common_csv}")
    print(f"- Summary JSON:      {summary_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
