#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reentrancy_guardian"))

from config import Config

DEFAULT_DATASET_ROOT = ROOT / "datasets" / "DAppSCAN-main" / "DAppSCAN-source"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "dappscan_source_swc107_reentrancy"
DEFAULT_PYTHON_EXE = ROOT / "venv" / "Scripts" / "python.exe"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"

PREDICTION_FIELDS = [
    "sample_id",
    "prediction",
    "status",
    "runtime_seconds",
    "total_findings",
    "classic_findings",
    "cross_contract_findings",
    "ror_findings",
    "source_path",
    "swc_count",
    "label_functions",
    "label_lines",
    "report_dir",
    "error",
]

LABEL_FIELDS = [
    "sample_id",
    "source_path",
    "swc_json_path",
    "category",
    "function",
    "line_number",
]


@dataclass(frozen=True)
class LabelRow:
    sample_id: str
    source_path: Path
    swc_json_path: Path
    category: str
    function: str
    line_number: str


@dataclass(frozen=True)
class Sample:
    sample_id: str
    source_path: Path
    labels: tuple[LabelRow, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate Reentrancy Guardian on DAppSCAN-source SWC-107 labelled source files."
    )
    parser.add_argument("--dataset-root", default=str(DEFAULT_DATASET_ROOT), help="DAppSCAN-source root.")
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--python-exe",
        default=str(DEFAULT_PYTHON_EXE if DEFAULT_PYTHON_EXE.exists() else Path(sys.executable)),
        help="Python executable used for detector subprocesses.",
    )
    parser.add_argument("--batch-size", type=int, default=25, help="Maximum new samples to run.")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent detector subprocesses.")
    parser.add_argument("--analysis-timeout", type=int, default=120, help="Timeout passed to the detector.")
    parser.add_argument("--process-timeout", type=int, default=240, help="Hard subprocess timeout.")
    parser.add_argument("--mode", choices=("full", "ccr", "ror"), default="full")
    parser.add_argument("--report-mode", choices=("none", "positives", "all"), default="positives")
    parser.add_argument(
        "--classic-fallback-policy",
        choices=Config.CLASSIC_FALLBACK_POLICY_CHOICES,
        default=Config.CLASSIC_FALLBACK_POLICY,
    )
    parser.add_argument("--no-precision-filter", action="store_true")
    parser.add_argument("--force", action="store_true", help="Clear existing predictions and rerun.")
    parser.add_argument(
        "--retry-status",
        action="append",
        choices=("compile_failed", "timeout", "analysis_failed", "runner_failed"),
        help="Treat existing records with this status as eligible for rerun. Can be passed multiple times.",
    )
    parser.add_argument("--skip-run", action="store_true", help="Regenerate labels/summary from cached predictions.")
    parser.add_argument("--dry-run", action="store_true", help="Write manifests but do not run the detector.")
    return parser.parse_args()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def trim_text(text: str | None, limit: int = 2000) -> str | None:
    if not text:
        return None
    compact = text.strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 15] + "\n...[truncated]"


def sanitize_id_part(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    return cleaned[:40] or "sample"


def source_from_file_path(dataset_root: Path, file_path: str) -> Path:
    prefix = "DAppSCAN-source/"
    rel = file_path[len(prefix) :] if file_path.startswith(prefix) else file_path
    return dataset_root / Path(rel.replace("/", os.sep))


def load_samples(dataset_root: Path) -> list[Sample]:
    swc_root = dataset_root / "SWCsource"
    grouped: dict[Path, list[dict[str, str]]] = {}

    for json_path in swc_root.rglob("*.json"):
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        file_path = str(payload.get("filePath") or "")
        if not file_path:
            continue
        source_path = source_from_file_path(dataset_root, file_path)
        for swc in payload.get("SWCs") or []:
            category = str(swc.get("category") or "")
            if not category.startswith("SWC-107"):
                continue
            if not source_path.exists():
                continue
            grouped.setdefault(source_path, []).append(
                {
                    "swc_json_path": str(json_path),
                    "category": category,
                    "function": str(swc.get("function") or ""),
                    "line_number": str(swc.get("lineNumber") or ""),
                }
            )

    samples: list[Sample] = []
    for index, source_path in enumerate(sorted(grouped, key=lambda p: display_path(p)), start=1):
        rel = display_path(source_path)
        digest = hashlib.sha1(rel.encode("utf-8")).hexdigest()[:8]
        sample_id = f"dappscan_{index:04d}_{sanitize_id_part(source_path.stem)}_{digest}"
        rows = tuple(
            LabelRow(
                sample_id=sample_id,
                source_path=source_path,
                swc_json_path=Path(row["swc_json_path"]),
                category=row["category"],
                function=row["function"],
                line_number=row["line_number"],
            )
            for row in grouped[source_path]
        )
        samples.append(Sample(sample_id=sample_id, source_path=source_path, labels=rows))
    return samples


def write_labels(path: Path, samples: list[Sample]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABEL_FIELDS)
        writer.writeheader()
        for sample in samples:
            for label in sample.labels:
                writer.writerow(
                    {
                        "sample_id": label.sample_id,
                        "source_path": display_path(label.source_path),
                        "swc_json_path": display_path(label.swc_json_path),
                        "category": label.category,
                        "function": label.function,
                        "line_number": label.line_number,
                    }
                )


def load_existing_records(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    records: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            records[str(record["sample_id"])] = record
    return records


def write_predictions_jsonl(path: Path, records: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for sample_id in sorted(records):
            handle.write(json.dumps(records[sample_id], ensure_ascii=False) + "\n")


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_predictions_csv(path: Path, records: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREDICTION_FIELDS)
        writer.writeheader()
        for sample_id in sorted(records):
            record = records[sample_id]
            writer.writerow({field: record.get(field) for field in PREDICTION_FIELDS})


def build_command(sample: Sample, temp_output_dir: Path, args: argparse.Namespace) -> list[str]:
    cmd = [
        args.python_exe,
        str(MAIN_SCRIPT),
        str(sample.source_path),
        "--json",
        "-o",
        str(temp_output_dir),
        "--timeout",
        str(args.analysis_timeout),
        "--classic-fallback-policy",
        args.classic_fallback_policy,
    ]
    if args.mode == "ccr":
        cmd.append("--ccr-only")
    elif args.mode == "ror":
        cmd.append("--ror-only")
    if args.classic_fallback_policy == "off":
        cmd.append("--no-classic-fallback")
    if args.no_precision_filter:
        cmd.append("--no-precision-filter")
    return cmd


def classify_failure(text: str | None, timeout: bool) -> str:
    if timeout:
        return "timeout"
    if not text:
        return "analysis_failed"
    if "Invalid compilation" in text or "Failed to load project" in text:
        return "compile_failed"
    return "analysis_failed"


def clean_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def move_or_replace(src: Path, dst: Path) -> None:
    clean_directory(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


def evaluate_sample(sample: Sample, args: argparse.Namespace, scratch_root: Path, reports_root: Path) -> dict[str, Any]:
    started = perf_counter()
    temp_output_dir = scratch_root / sample.sample_id
    final_report_dir = reports_root / sample.sample_id
    report_path = temp_output_dir / "vulnerabilities.json"
    clean_directory(temp_output_dir)

    completed: subprocess.CompletedProcess[str] | None = None
    timeout = False
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        completed = subprocess.run(
            build_command(sample, temp_output_dir, args),
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=args.process_timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        timeout = True

    runtime_seconds = perf_counter() - started
    output_text = ""
    if completed is not None:
        output_text = (completed.stdout or "") + "\n" + (completed.stderr or "")

    if completed is None or completed.returncode != 0 or not report_path.exists():
        clean_directory(temp_output_dir)
        return {
            "sample_id": sample.sample_id,
            "prediction": None,
            "status": classify_failure(output_text, timeout),
            "runtime_seconds": runtime_seconds,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "source_path": display_path(sample.source_path),
            "swc_count": len(sample.labels),
            "label_functions": ";".join(sorted({label.function for label in sample.labels if label.function})),
            "label_lines": ";".join(label.line_number for label in sample.labels if label.line_number),
            "report_dir": None,
            "error": trim_text(output_text or f"Process timeout after {args.process_timeout}s"),
        }

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    summary = report_data.get("summary", {})
    total_findings = int(summary.get("total_vulnerabilities", 0))
    prediction = 1 if total_findings > 0 else 0
    kept_report_dir = None
    if args.report_mode == "all" or (args.report_mode == "positives" and prediction == 1):
        move_or_replace(temp_output_dir, final_report_dir)
        kept_report_dir = display_path(final_report_dir)
    else:
        clean_directory(temp_output_dir)

    return {
        "sample_id": sample.sample_id,
        "prediction": prediction,
        "status": "ok",
        "runtime_seconds": runtime_seconds,
        "total_findings": total_findings,
        "classic_findings": int(summary.get("classic_reentrancy_count", 0)),
        "cross_contract_findings": int(summary.get("cross_contract_reentrancy_count", 0)),
        "ror_findings": int(summary.get("ror_count", 0)),
        "source_path": display_path(sample.source_path),
        "swc_count": len(sample.labels),
        "label_functions": ";".join(sorted({label.function for label in sample.labels if label.function})),
        "label_lines": ";".join(label.line_number for label in sample.labels if label.line_number),
        "report_dir": kept_report_dir,
        "error": None,
    }


def summarize(samples: list[Sample], records: dict[str, dict[str, Any]], args: argparse.Namespace, selected: list[Sample]) -> dict[str, Any]:
    statuses = Counter(str(record.get("status", "unknown")) for record in records.values())
    ok_records = [record for record in records.values() if record.get("status") == "ok"]
    positives = [record for record in ok_records if record.get("prediction") == 1]
    negatives = [record for record in ok_records if record.get("prediction") == 0]
    runtimes = [float(record["runtime_seconds"]) for record in ok_records if record.get("runtime_seconds") is not None]
    completed = set(records)
    return {
        "dataset_summary": {
            "dataset_root": display_path(Path(args.dataset_root)),
            "swc107_label_rows": sum(len(sample.labels) for sample in samples),
            "swc107_unique_source_files": len(samples),
            "completed_records_in_output": len(completed),
            "remaining_after_this_run": len(samples) - len(completed),
            "output_dir": display_path(Path(args.output_dir)),
        },
        "batch_summary": {
            "selected_count": len(selected),
            "first_sample_id": selected[0].sample_id if selected else None,
            "last_sample_id": selected[-1].sample_id if selected else None,
            "batch_size": args.batch_size,
            "workers": args.workers,
            "dry_run": bool(args.dry_run),
            "skip_run": bool(args.skip_run),
        },
        "status_summary": dict(sorted(statuses.items())),
        "positive_label_metrics": {
            "compilable_ok_samples": len(ok_records),
            "detected_positive_samples": len(positives),
            "missed_compilable_positive_samples": len(negatives),
            "recall_on_compilable_samples": (len(positives) / len(ok_records) if ok_records else None),
            "coverage_including_failures": (len(positives) / len(samples) if samples else None),
            "avg_ok_runtime_seconds": (sum(runtimes) / len(runtimes) if runtimes else None),
        },
        "run_config": {
            "mode": args.mode,
            "analysis_timeout": args.analysis_timeout,
            "process_timeout": args.process_timeout,
            "classic_fallback_policy": args.classic_fallback_policy,
            "precision_filter": not args.no_precision_filter,
            "python_exe": args.python_exe,
        },
    }


def main() -> int:
    args = parse_args()
    dataset_root = Path(args.dataset_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    args.dataset_root = str(dataset_root)
    args.output_dir = str(output_dir)

    if not dataset_root.exists():
        print(f"Dataset root does not exist: {dataset_root}")
        return 1
    if not Path(args.python_exe).exists():
        print(f"Python executable does not exist: {args.python_exe}")
        return 1

    predictions_jsonl = output_dir / "predictions.jsonl"
    predictions_csv = output_dir / "predictions.csv"
    labels_csv = output_dir / "labels.csv"
    summary_json = output_dir / "summary.json"
    scratch_root = output_dir / "_tmp"
    reports_root = output_dir / "reports"

    if args.force and not args.skip_run and not args.dry_run:
        predictions_jsonl.unlink(missing_ok=True)
        clean_directory(scratch_root)
        clean_directory(reports_root)

    samples = load_samples(dataset_root)
    write_labels(labels_csv, samples)
    records = load_existing_records(predictions_jsonl)
    retry_statuses = set(args.retry_status or [])
    retry_ids = {
        sample_id
        for sample_id, record in records.items()
        if str(record.get("status") or "") in retry_statuses
    }
    selected = [
        sample
        for sample in samples
        if sample.sample_id not in records or sample.sample_id in retry_ids
    ][: args.batch_size]

    print(f"SWC-107 label rows: {sum(len(sample.labels) for sample in samples)}")
    print(f"SWC-107 unique source files: {len(samples)}")
    print(f"Already completed in this output: {len(records)}")
    if retry_statuses:
        print(f"Retry statuses: {', '.join(sorted(retry_statuses))}; eligible existing records: {len(retry_ids)}")
    print(f"Selected batch size: {len(selected)}")
    if selected:
        print(f"Batch range: {selected[0].sample_id} -> {selected[-1].sample_id}")

    output_dir.mkdir(parents=True, exist_ok=True)
    if args.dry_run or args.skip_run or not selected:
        write_predictions_jsonl(predictions_jsonl, records)
        write_predictions_csv(predictions_csv, records)
        summary_json.write_text(json.dumps(summarize(samples, records, args, selected), indent=2), encoding="utf-8")
        return 0

    scratch_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(evaluate_sample, sample, args, scratch_root, reports_root): sample for sample in selected}
        for completed_count, future in enumerate(as_completed(futures), start=1):
            sample = futures[future]
            try:
                record = future.result()
            except Exception as exc:
                record = {
                    "sample_id": sample.sample_id,
                    "prediction": None,
                    "status": "runner_failed",
                    "runtime_seconds": None,
                    "total_findings": None,
                    "classic_findings": None,
                    "cross_contract_findings": None,
                    "ror_findings": None,
                    "source_path": display_path(sample.source_path),
                    "swc_count": len(sample.labels),
                    "label_functions": ";".join(sorted({label.function for label in sample.labels if label.function})),
                    "label_lines": ";".join(label.line_number for label in sample.labels if label.line_number),
                    "report_dir": None,
                    "error": trim_text(str(exc)),
                }
            records[record["sample_id"]] = record
            append_jsonl(predictions_jsonl, record)
            print(
                f"[{completed_count}/{len(selected)}] {record['sample_id']} -> "
                f"status={record['status']}, prediction={record['prediction']}, findings={record['total_findings']}"
            )

    write_predictions_jsonl(predictions_jsonl, records)
    write_predictions_csv(predictions_csv, records)
    summary_json.write_text(json.dumps(summarize(samples, records, args, selected), indent=2), encoding="utf-8")
    print("\nArtifacts written:")
    print(f"- Labels CSV:       {labels_csv}")
    print(f"- Predictions JSONL:{predictions_jsonl}")
    print(f"- Predictions CSV:  {predictions_csv}")
    print(f"- Summary JSON:     {summary_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
