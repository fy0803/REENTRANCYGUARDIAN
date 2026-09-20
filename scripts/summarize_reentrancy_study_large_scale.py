#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_CSV = ROOT / "datasets" / "ReentrancyStudy-Data" / "reentrancy_information.csv"
DEFAULT_GUARDIAN_CSV = ROOT / "results" / "exp_large_db2_guardian" / "predictions.csv"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "experiment_tables"
TOOLS = ["oyente", "mythril", "securify1", "securify2", "smartian", "sailfish"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare ReentrancyStudy DB2 and summarize large-scale Guardian results against "
            "the ReentrancyStudy baseline tool outputs."
        )
    )
    parser.add_argument("--dataset-csv", default=str(DEFAULT_DATASET_CSV))
    parser.add_argument("--guardian-predictions", default=str(DEFAULT_GUARDIAN_CSV))
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument(
        "--failed-as-negative",
        action="store_true",
        help="Use SliSE-style scoring: Guardian failures/timeouts/not-run count as prediction=0.",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: Iterable[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = rows[0].keys() if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def pct(numerator: int | float, denominator: int | float) -> float | None:
    if denominator == 0:
        return None
    return float(numerator) / float(denominator)


def fmt(value: Any, digits: int = 4) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, int):
        return str(value)
    return f"{float(value):.{digits}f}"


def tool_positive(row: dict[str, str], tool: str) -> bool:
    return row.get(tool, "").strip() == "1"


def select_db2_rows(dataset_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in dataset_rows if any(tool_positive(row, tool) for tool in TOOLS)]


def load_guardian_records(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    rows = read_csv(path)
    return {row["address"].strip().lower(): row for row in rows if row.get("address")}


def guardian_prediction(record: dict[str, str] | None, failed_as_negative: bool) -> int | None:
    if record is None:
        return None
    if record.get("status") == "ok":
        return 1 if str(record.get("prediction", "")).strip() == "1" else 0
    return 0 if failed_as_negative else None


def binary_metrics(labels: list[int], predictions: list[int]) -> dict[str, Any]:
    tp = sum(1 for y, p in zip(labels, predictions) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, predictions) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, predictions) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, predictions) if y == 1 and p == 0)
    precision = pct(tp, tp + fp)
    recall = pct(tp, tp + fn)
    f1 = None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "evaluated": len(labels),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": pct(tp + tn, len(labels)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": pct(fp, fp + tn),
        "fnr": pct(fn, fn + tp),
    }


def runtime_summary(records: Iterable[dict[str, str]]) -> dict[str, Any]:
    values = sorted(
        float(record["runtime_seconds"])
        for record in records
        if record.get("runtime_seconds") not in (None, "")
    )
    if not values:
        return {"avg": None, "median": None, "p95": None, "max": None, "sum": None}
    p95_index = min(len(values) - 1, int(len(values) * 0.95))
    return {
        "avg": mean(values),
        "median": median(values),
        "p95": values[p95_index],
        "max": max(values),
        "sum": sum(values),
    }


def build_baseline_metrics(db2_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    metrics_rows: list[dict[str, Any]] = []
    labels = [1 if row["true_positive"] == "1" else 0 for row in db2_rows]
    for tool in TOOLS:
        predictions = [1 if tool_positive(row, tool) else 0 for row in db2_rows]
        metrics = binary_metrics(labels, predictions)
        metrics_rows.append({"tool": tool, "coverage": 1.0, **metrics})
    return metrics_rows


def build_guardian_metrics(
    db2_rows: list[dict[str, str]],
    guardian_records: dict[str, dict[str, str]],
    failed_as_negative: bool,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    evaluated_rows: list[dict[str, str]] = []
    predictions: list[int] = []
    labels: list[int] = []
    for row in db2_rows:
        address = row["address"].strip().lower()
        prediction = guardian_prediction(guardian_records.get(address), failed_as_negative)
        if prediction is None:
            continue
        evaluated_rows.append(row)
        predictions.append(prediction)
        labels.append(1 if row["true_positive"] == "1" else 0)

    metrics = binary_metrics(labels, predictions)
    metrics["coverage"] = pct(len(evaluated_rows), len(db2_rows))
    return metrics, evaluated_rows


def build_overlap_rows(db2_rows: list[dict[str, str]], guardian_records: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in db2_rows:
        address = row["address"].strip().lower()
        guardian_record = guardian_records.get(address)
        guardian_pos = guardian_record is not None and guardian_record.get("status") == "ok" and guardian_record.get("prediction") == "1"
        baseline_tools = [tool for tool in TOOLS if tool_positive(row, tool)]
        baseline_pos = bool(baseline_tools)
        if guardian_pos or baseline_pos:
            rows.append(
                {
                    "address": address,
                    "true_positive": row["true_positive"],
                    "guardian_status": guardian_record.get("status") if guardian_record else "not_run",
                    "guardian_prediction": guardian_record.get("prediction") if guardian_record else "",
                    "guardian_findings": guardian_record.get("total_findings") if guardian_record else "",
                    "baseline_tools": ";".join(baseline_tools),
                    "guardian_only": int(guardian_pos and not baseline_pos),
                    "baseline_only": int(baseline_pos and not guardian_pos),
                    "common_positive": int(guardian_pos and baseline_pos),
                }
            )
    return rows


def build_markdown(
    output_path: Path,
    summary: dict[str, Any],
    metric_rows: list[dict[str, Any]],
    overlap_summary: dict[str, Any],
) -> None:
    lines = [
        "# Large-Scale ReentrancyStudy Summary",
        "",
        "## Dataset",
        "",
        f"- Total ReentrancyStudy rows: {summary['dataset']['total_rows']}",
        f"- DB2 rows (baseline-union positives): {summary['dataset']['db2_rows']}",
        f"- DB2 positives: {summary['dataset']['db2_positive_rows']}",
        f"- DB2 negatives: {summary['dataset']['db2_negative_rows']}",
        "",
        "## Guardian Run",
        "",
        f"- Records loaded: {summary['guardian']['records_loaded']}",
        f"- Records in DB2: {summary['guardian']['records_in_db2']}",
        f"- Status counts: {summary['guardian']['status_counts']}",
        f"- Runtime avg / median / p95: {fmt(summary['guardian']['runtime']['avg'])} / "
        f"{fmt(summary['guardian']['runtime']['median'])} / {fmt(summary['guardian']['runtime']['p95'])}",
        "",
        "## Metrics",
        "",
        "| Tool | Evaluated | Coverage | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in metric_rows:
        lines.append(
            f"| `{row['tool']}` | {row['evaluated']} | {fmt(row['coverage'])} | {row['tp']} | {row['fp']} | "
            f"{row['tn']} | {row['fn']} | {fmt(row['precision'])} | {fmt(row['recall'])} | "
            f"{fmt(row['f1'])} | {fmt(row['fpr'])} |"
        )

    lines.extend(
        [
            "",
            "## Overlap",
            "",
            f"- Guardian positives in DB2: {overlap_summary['guardian_positive']}",
            f"- Common positives: {overlap_summary['common_positive']}",
            f"- Guardian-only positives: {overlap_summary['guardian_only']}",
            f"- Baseline-only positives: {overlap_summary['baseline_only']}",
        ]
    )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    dataset_csv = Path(args.dataset_csv)
    guardian_csv = Path(args.guardian_predictions)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_rows = read_csv(dataset_csv)
    db2_rows = select_db2_rows(dataset_rows)
    guardian_records = load_guardian_records(guardian_csv)
    db2_addresses = {row["address"].strip().lower() for row in db2_rows}
    guardian_db2_records = {
        address: record for address, record in guardian_records.items() if address in db2_addresses
    }

    db2_addresses_path = output_dir / "reentrancy_study_db2_addresses.txt"
    db2_addresses_path.write_text("\n".join(sorted(db2_addresses)) + "\n", encoding="utf-8")

    status_counts: dict[str, int] = {}
    for record in guardian_db2_records.values():
        status = record.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    baseline_metrics = build_baseline_metrics(db2_rows)
    guardian_metrics, _ = build_guardian_metrics(db2_rows, guardian_records, args.failed_as_negative)
    metric_rows = [{"tool": "reentrancy_guardian", **guardian_metrics}, *baseline_metrics]

    overlap_rows = build_overlap_rows(db2_rows, guardian_records)
    guardian_positive = sum(1 for row in overlap_rows if row["guardian_prediction"] == "1")
    common_positive = sum(1 for row in overlap_rows if row["common_positive"] == 1)
    guardian_only = sum(1 for row in overlap_rows if row["guardian_only"] == 1)
    baseline_only = sum(1 for row in overlap_rows if row["baseline_only"] == 1)
    overlap_summary = {
        "guardian_positive": guardian_positive,
        "common_positive": common_positive,
        "guardian_only": guardian_only,
        "baseline_only": baseline_only,
    }

    summary = {
        "dataset": {
            "dataset_csv": display_path(dataset_csv),
            "total_rows": len(dataset_rows),
            "db2_rows": len(db2_rows),
            "db2_positive_rows": sum(1 for row in db2_rows if row["true_positive"] == "1"),
            "db2_negative_rows": sum(1 for row in db2_rows if row["true_positive"] != "1"),
            "db2_addresses": display_path(db2_addresses_path),
        },
        "guardian": {
            "predictions_csv": display_path(guardian_csv),
            "records_loaded": len(guardian_records),
            "records_in_db2": len(guardian_db2_records),
            "failed_as_negative": bool(args.failed_as_negative),
            "status_counts": dict(sorted(status_counts.items())),
            "runtime": runtime_summary(guardian_db2_records.values()),
        },
        "overlap": overlap_summary,
        "metrics": metric_rows,
    }

    metrics_csv = output_dir / "reentrancy_study_db2_metrics.csv"
    overlap_csv = output_dir / "reentrancy_study_db2_overlap.csv"
    summary_json = output_dir / "reentrancy_study_db2_large_scale_summary.json"
    summary_md = output_dir / "reentrancy_study_db2_large_scale_summary.md"

    write_csv(metrics_csv, metric_rows)
    write_csv(overlap_csv, overlap_rows)
    write_json(summary_json, summary)
    build_markdown(summary_md, summary, metric_rows, overlap_summary)

    print("Artifacts written:")
    print(f"- DB2 addresses: {db2_addresses_path}")
    print(f"- Metrics CSV:   {metrics_csv}")
    print(f"- Overlap CSV:   {overlap_csv}")
    print(f"- Summary JSON:  {summary_json}")
    print(f"- Summary MD:    {summary_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
