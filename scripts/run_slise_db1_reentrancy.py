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

DEFAULT_DATASET_DIR = Path(r"D:\code\SliSE-main\Datasets\DB1\All_contract")
DEFAULT_REFERENCE_CSV = Path(r"D:\code\SliSE-main\Experimental_data\RQ1\stage1&2_detection_DB1.csv")
DEFAULT_OUTPUT_DIR = ROOT / "results" / "slise_db1_reentrancy"
DEFAULT_PYTHON_EXE = ROOT / "venv" / "Scripts" / "python.exe"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"

PREDICTION_FIELDS = [
    "sample_id",
    "filename",
    "content_hash",
    "duplicate_of",
    "prediction",
    "status",
    "runtime_seconds",
    "total_findings",
    "classic_findings",
    "cross_contract_findings",
    "ror_findings",
    "reference_label",
    "reference_runtime_seconds",
    "source_path",
    "report_dir",
    "error",
]

MANIFEST_FIELDS = [
    "sample_id",
    "filename",
    "content_hash",
    "duplicate_of",
    "source_path",
    "reference_label",
    "reference_runtime_seconds",
]


@dataclass(frozen=True)
class Sample:
    sample_id: str
    filename: str
    source_path: Path
    content_hash: str
    duplicate_of: str | None
    reference_label: str | None
    reference_runtime_seconds: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Reentrancy Guardian on SliSE DB1 All_contract Solidity files."
    )
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR), help="Directory with DB1 .sol files.")
    parser.add_argument(
        "--reference-csv",
        default=str(DEFAULT_REFERENCE_CSV),
        help="Optional SliSE RQ1 stage1&2_detection_DB1.csv used only as a reference column.",
    )
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
        "--bounded-ccr",
        action="store_true",
        help="Enable reduced-precision CCR limits for large-contract timeout retries.",
    )
    parser.add_argument(
        "--ccr-state-limit",
        type=int,
        help="Maximum execution states explored per CCR reachability query in bounded CCR mode.",
    )
    parser.add_argument(
        "--ccr-time-budget",
        type=int,
        help="Maximum seconds spent in CCR detection in bounded CCR mode.",
    )
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
    parser.add_argument("--skip-run", action="store_true", help="Regenerate manifest/summary from cached predictions.")
    parser.add_argument("--dry-run", action="store_true", help="Write manifest but do not run the detector.")
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
    return cleaned[:60] or "sample"


def load_reference_labels(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    labels: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            filename = Path(row.get("Filename", "")).name
            if not filename:
                continue
            labels[filename] = {
                "reference_label": row.get("Label", "") or "",
                "reference_runtime_seconds": row.get("Value", "") or "",
            }
    return labels


def load_samples(dataset_dir: Path, reference_csv: Path) -> list[Sample]:
    reference = load_reference_labels(reference_csv)
    samples: list[Sample] = []
    first_sample_by_hash: dict[str, str] = {}

    for index, source_path in enumerate(sorted(dataset_dir.glob("*.sol"), key=lambda p: p.name.lower()), start=1):
        filename = source_path.name
        ref = reference.get(filename, {})
        sample_id = f"db1_{index:04d}_{sanitize_id_part(source_path.stem)}"
        content_hash = hashlib.sha1(source_path.read_bytes()).hexdigest()
        duplicate_of = first_sample_by_hash.get(content_hash)
        first_sample_by_hash.setdefault(content_hash, sample_id)
        samples.append(
            Sample(
                sample_id=sample_id,
                filename=filename,
                source_path=source_path,
                content_hash=content_hash,
                duplicate_of=duplicate_of,
                reference_label=ref.get("reference_label") or None,
                reference_runtime_seconds=ref.get("reference_runtime_seconds") or None,
            )
        )
    return samples


def write_manifest(path: Path, samples: list[Sample]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        for sample in samples:
            writer.writerow(
                {
                    "sample_id": sample.sample_id,
                    "filename": sample.filename,
                    "content_hash": sample.content_hash,
                    "duplicate_of": sample.duplicate_of,
                    "source_path": display_path(sample.source_path),
                    "reference_label": sample.reference_label,
                    "reference_runtime_seconds": sample.reference_runtime_seconds,
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
    if args.bounded_ccr:
        cmd.append("--bounded-ccr")
        if args.ccr_state_limit is not None:
            cmd.extend(["--ccr-state-limit", str(args.ccr_state_limit)])
        if args.ccr_time_budget is not None:
            cmd.extend(["--ccr-time-budget", str(args.ccr_time_budget)])
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


def base_record(sample: Sample) -> dict[str, Any]:
    return {
        "sample_id": sample.sample_id,
        "filename": sample.filename,
        "content_hash": sample.content_hash,
        "duplicate_of": sample.duplicate_of,
        "reference_label": sample.reference_label,
        "reference_runtime_seconds": sample.reference_runtime_seconds,
        "source_path": display_path(sample.source_path),
    }


def clone_record_for_duplicate(sample: Sample, source_record: dict[str, Any]) -> dict[str, Any]:
    cloned = dict(source_record)
    cloned.update(base_record(sample))
    cloned["duplicate_of"] = source_record["sample_id"]
    return cloned


def fill_duplicate_records(samples: list[Sample], records: dict[str, dict[str, Any]], retry_statuses: set[str]) -> None:
    samples_by_id = {sample.sample_id: sample for sample in samples}
    record_by_hash: dict[str, dict[str, Any]] = {}

    for sample_id, record in list(records.items()):
        sample = samples_by_id.get(sample_id)
        if not sample:
            continue
        record.setdefault("content_hash", sample.content_hash)
        record.setdefault("duplicate_of", sample.duplicate_of)
        if str(record.get("status") or "") in retry_statuses:
            continue
        record_by_hash.setdefault(sample.content_hash, record)

    for sample in samples:
        if sample.sample_id in records:
            continue
        source_record = record_by_hash.get(sample.content_hash)
        if not source_record:
            continue
        records[sample.sample_id] = clone_record_for_duplicate(sample, source_record)


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
        record = base_record(sample)
        record.update(
            {
                "prediction": None,
                "status": classify_failure(output_text, timeout),
                "runtime_seconds": runtime_seconds,
                "total_findings": None,
                "classic_findings": None,
                "cross_contract_findings": None,
                "ror_findings": None,
                "report_dir": None,
                "error": trim_text(output_text or f"Process timeout after {args.process_timeout}s"),
            }
        )
        return record

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

    record = base_record(sample)
    record.update(
        {
            "prediction": prediction,
            "status": "ok",
            "runtime_seconds": runtime_seconds,
            "total_findings": total_findings,
            "classic_findings": int(summary.get("classic_reentrancy_count", 0)),
            "cross_contract_findings": int(summary.get("cross_contract_reentrancy_count", 0)),
            "ror_findings": int(summary.get("ror_count", 0)),
            "report_dir": kept_report_dir,
            "error": None,
        }
    )
    return record


def summarize(samples: list[Sample], records: dict[str, dict[str, Any]], args: argparse.Namespace, selected: list[Sample]) -> dict[str, Any]:
    statuses = Counter(str(record.get("status", "unknown")) for record in records.values())
    ok_records = [record for record in records.values() if record.get("status") == "ok"]
    positives = [record for record in ok_records if record.get("prediction") == 1]
    negatives = [record for record in ok_records if record.get("prediction") == 0]
    runtimes = [float(record["runtime_seconds"]) for record in ok_records if record.get("runtime_seconds") is not None]
    reference_counts = Counter(sample.reference_label or "unlabeled" for sample in samples)
    unique_hashes = {sample.content_hash for sample in samples}
    completed_hashes = {str(record.get("content_hash") or "") for record in records.values() if record.get("content_hash")}
    completed = set(records)
    return {
        "dataset_summary": {
            "dataset_dir": display_path(Path(args.dataset_dir)),
            "total_solidity_files": len(samples),
            "unique_source_hashes": len(unique_hashes),
            "reference_label_counts": dict(sorted(reference_counts.items())),
            "completed_records_in_output": len(completed),
            "completed_unique_hashes_in_output": len(completed_hashes),
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
        "prediction_summary": {
            "ok_samples": len(ok_records),
            "detected_positive_samples": len(positives),
            "detected_negative_samples": len(negatives),
            "positive_rate_on_ok_samples": (len(positives) / len(ok_records) if ok_records else None),
            "avg_ok_runtime_seconds": (sum(runtimes) / len(runtimes) if runtimes else None),
        },
        "run_config": {
            "mode": args.mode,
            "analysis_timeout": args.analysis_timeout,
            "process_timeout": args.process_timeout,
            "classic_fallback_policy": args.classic_fallback_policy,
            "bounded_ccr": bool(args.bounded_ccr),
            "ccr_state_limit": args.ccr_state_limit,
            "ccr_time_budget": args.ccr_time_budget,
            "precision_filter": not args.no_precision_filter,
            "python_exe": args.python_exe,
            "reference_csv": display_path(Path(args.reference_csv)),
        },
    }


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir).resolve()
    reference_csv = Path(args.reference_csv).resolve()
    output_dir = Path(args.output_dir).resolve()
    args.dataset_dir = str(dataset_dir)
    args.reference_csv = str(reference_csv)
    args.output_dir = str(output_dir)

    if not dataset_dir.exists():
        print(f"Dataset directory does not exist: {dataset_dir}")
        return 1
    if not Path(args.python_exe).exists():
        print(f"Python executable does not exist: {args.python_exe}")
        return 1

    predictions_jsonl = output_dir / "predictions.jsonl"
    predictions_csv = output_dir / "predictions.csv"
    manifest_csv = output_dir / "manifest.csv"
    summary_json = output_dir / "summary.json"
    scratch_root = output_dir / "_tmp"
    reports_root = output_dir / "reports"

    if args.force and not args.skip_run and not args.dry_run:
        predictions_jsonl.unlink(missing_ok=True)
        clean_directory(scratch_root)
        clean_directory(reports_root)

    samples = load_samples(dataset_dir, reference_csv)
    write_manifest(manifest_csv, samples)
    records = load_existing_records(predictions_jsonl)
    retry_statuses = set(args.retry_status or [])
    fill_duplicate_records(samples, records, retry_statuses)
    retry_ids = {
        sample_id
        for sample_id, record in records.items()
        if str(record.get("status") or "") in retry_statuses
    }
    selected: list[Sample] = []
    if args.batch_size > 0:
        selected_hashes = {
            str(record.get("content_hash") or "")
            for sample_id, record in records.items()
            if sample_id not in retry_ids and record.get("content_hash")
        }
        for sample in samples:
            if sample.sample_id in records and sample.sample_id not in retry_ids:
                continue
            if sample.content_hash in selected_hashes and sample.sample_id not in retry_ids:
                continue
            selected.append(sample)
            selected_hashes.add(sample.content_hash)
            if len(selected) >= args.batch_size:
                break

    reference_counts = Counter(sample.reference_label or "unlabeled" for sample in samples)
    print(f"DB1 Solidity files: {len(samples)}")
    print(f"DB1 unique source hashes: {len({sample.content_hash for sample in samples})}")
    print(f"Reference label counts: {dict(sorted(reference_counts.items()))}")
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
                record = base_record(sample)
                record.update(
                    {
                        "prediction": None,
                        "status": "runner_failed",
                        "runtime_seconds": None,
                        "total_findings": None,
                        "classic_findings": None,
                        "cross_contract_findings": None,
                        "ror_findings": None,
                        "report_dir": None,
                        "error": trim_text(str(exc)),
                    }
                )
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
    print(f"- Manifest CSV:     {manifest_csv}")
    print(f"- Predictions JSONL:{predictions_jsonl}")
    print(f"- Predictions CSV:  {predictions_csv}")
    print(f"- Summary JSON:     {summary_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
