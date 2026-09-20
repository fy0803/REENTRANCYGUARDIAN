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
sys.path.insert(0, str(ROOT / "reentrancy_guardian"))

from config import Config

DEFAULT_CONTRACTS_DIR = ROOT / "datasets" / "ReentrancyStudy-Data" / "deduplicated_smart_contracts"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "reentrancy_study_full_batches"
DEFAULT_SEED_PREDICTIONS = ROOT / "results" / "precision_filter_v3_e2e_check" / "predictions.csv"
DEFAULT_PYTHON_EXE = ROOT / "venv" / "Scripts" / "python.exe"
MAIN_SCRIPT = ROOT / "reentrancy_guardian" / "main.py"

RECORD_FIELDS = [
    "address",
    "prediction",
    "status",
    "analysis_mode",
    "bounded_retry",
    "runtime_seconds",
    "exact_timeout_seconds",
    "total_findings",
    "classic_findings",
    "cross_contract_findings",
    "ror_findings",
    "contract_path",
    "report_dir",
    "error",
    "notes",
]


@dataclass(frozen=True)
class ContractJob:
    address: str
    contract_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Reentrancy Guardian on the remaining ReentrancyStudy-Data contracts in resumable batches."
        )
    )
    parser.add_argument(
        "--contracts-dir",
        default=str(DEFAULT_CONTRACTS_DIR),
        help="Directory containing deduplicated Solidity contracts named by address.",
    )
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--python-exe",
        default=str(DEFAULT_PYTHON_EXE if DEFAULT_PYTHON_EXE.exists() else Path(sys.executable)),
        help="Python executable used for each detector subprocess.",
    )
    parser.add_argument("--batch-size", type=int, default=100, help="Number of new contracts to process this run.")
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(4, os.cpu_count() or 1)),
        help="Number of concurrent subprocess workers.",
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
        "--mode",
        choices=("full", "ccr", "ror"),
        default="full",
        help="Run the full detector, CCR-only mode, or ROR-only mode.",
    )
    parser.add_argument(
        "--report-mode",
        choices=("none", "positives", "all"),
        default="positives",
        help="Keep no reports, only positive reports, or every per-contract JSON report.",
    )
    parser.add_argument(
        "--skip-seed-predictions",
        default=str(DEFAULT_SEED_PREDICTIONS),
        help="Existing predictions CSV/JSONL whose addresses should be skipped as already processed.",
    )
    parser.add_argument(
        "--no-skip-seed-predictions",
        action="store_true",
        help="Do not skip the default labelled-subset predictions.",
    )
    parser.add_argument(
        "--addresses-file",
        help="Optional text file with one contract address per line. Only these addresses are eligible.",
    )
    parser.add_argument("--start-after", help="Only consider addresses lexicographically after this address.")
    parser.add_argument("--force", action="store_true", help="Clear this output directory's cache and rerun.")
    parser.add_argument("--skip-run", action="store_true", help="Regenerate CSV/summary from cached JSONL only.")
    parser.add_argument("--dry-run", action="store_true", help="Show the next batch without running analysis.")
    parser.add_argument(
        "--no-precision-filter",
        action="store_true",
        help="Disable conservative false-positive suppression filters in Reentrancy Guardian.",
    )
    parser.add_argument(
        "--no-classic-fallback",
        action="store_true",
        help="Disable same-contract classic fallback callbacks in Reentrancy Guardian.",
    )
    parser.add_argument(
        "--classic-fallback-policy",
        choices=Config.CLASSIC_FALLBACK_POLICY_CHOICES,
        default=Config.CLASSIC_FALLBACK_POLICY,
        help=(
            "Classic fallback handling passed to Reentrancy Guardian: normal, strict_v6 "
            "(alias: strict/strict-v6), aggressive, or off. --no-classic-fallback is kept as an alias for off."
        ),
    )
    parser.add_argument(
        "--bounded-ccr",
        action="store_true",
        help="Enable reduced-precision CCR limits for large-contract coverage diagnostics.",
    )
    parser.add_argument("--ccr-state-limit", type=int, help="CCR state limit when --bounded-ccr is enabled.")
    parser.add_argument("--ccr-time-budget", type=int, help="CCR time budget when --bounded-ccr is enabled.")
    parser.add_argument(
        "--retry-timeout-with-bounded-ccr",
        action="store_true",
        help=(
            "If an exact full/CCR run hits the process timeout, retry the same contract once "
            "with bounded CCR and mark the record as a reduced-precision retry."
        ),
    )
    parser.add_argument(
        "--retry-existing-timeouts",
        action="store_true",
        help="When resuming, treat existing timeout records as eligible for rerun.",
    )
    parser.add_argument(
        "--retry-existing-failures",
        action="store_true",
        help="When resuming, treat existing analysis_failed records as eligible for rerun.",
    )
    parser.add_argument(
        "--ablation-no-callback-edges",
        action="store_true",
        help=(
            "Disable SE-ICFG callback edge generation while keeping classic fallback "
            "callback handling controlled by the classic fallback policy."
        ),
    )
    parser.add_argument("--ablation-no-cross-contract-path-recovery", action="store_true")
    parser.add_argument(
        "--ablation-no-state-access-semantics",
        action="store_true",
        help="Disable extraction/injection of node-level state read/write dependencies.",
    )
    parser.add_argument(
        "--ablation-no-state-access-propagation",
        action="store_true",
        help=(
            "Keep node-level reads/writes but disable interprocedural state-access "
            "propagation through calls, callbacks, and read-only query inlining."
        ),
    )
    parser.add_argument(
        "--ablation-explicit-state-conflict-only",
        action="store_true",
        help=(
            "Require explicit pre-write/post-access state overlap and disable loose "
            "post-write or implicit-balance state-conflict recovery."
        ),
    )
    parser.add_argument("--ablation-no-state-conflict", action="store_true")
    parser.add_argument("--ablation-no-lock-context", action="store_true")
    parser.add_argument("--ablation-no-path-constraints", action="store_true")
    parser.add_argument("--ablation-no-ror-mismatch-window", action="store_true")
    parser.add_argument("--ablation-no-ror-propagation", action="store_true")
    parser.add_argument("--ablation-no-ror-sensitive-sink", action="store_true")
    parser.add_argument(
        "--ablation-no-icfg-modeling",
        action="store_true",
        help=(
            "Run the no-SE-ICFG graph ablation: keep intraprocedural CFG nodes and normalized "
            "node facts, but remove call/return stitching, semantic edges, lock scopes, "
            "and mismatch-window modeling."
        ),
    )
    parser.add_argument(
        "--ablation-no-se-icfg-modeling-strict",
        action="store_true",
        help=(
            "Strict no-SE-ICFG ablation: use only intraprocedural CFG nodes/edges, "
            "disable semantic edges, lock scopes, mismatch windows, delegatecall storage "
            "ownership, and classic fallback callback compensation."
        ),
    )
    parser.add_argument(
        "--ablation-no-semantic-enhancement",
        action="store_true",
        help=(
            "Disable the SE-ICFG semantic enhancement layer: function call/return relations, "
            "cross-contract call recovery, external reentrant windows, mismatch windows, "
            "readonly propagation, lock scopes, and delegatecall storage ownership semantics."
        ),
    )
    parser.add_argument(
        "--ablation-intra-contract-only",
        action="store_true",
        help=(
            "Use function-local and same-contract call/return edges only; disable "
            "cross-contract call/return stitching and cross-contract callback recovery."
        ),
    )
    return parser.parse_args()


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


def load_address_filter(path: str | None) -> Optional[set[str]]:
    if not path:
        return None
    values = {
        line.strip().lower()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    return values or None


def iter_contract_jobs(contracts_dir: Path, address_filter: Optional[set[str]], start_after: str | None) -> list[ContractJob]:
    threshold = start_after.lower() if start_after else None
    jobs: list[ContractJob] = []
    for path in contracts_dir.glob("*.sol"):
        address = path.stem.lower()
        if address_filter and address not in address_filter:
            continue
        if threshold and address <= threshold:
            continue
        jobs.append(ContractJob(address=address, contract_path=path))
    return sorted(jobs, key=lambda job: job.address)


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
            address = str(record.get("address", "")).lower()
            if address:
                records[address] = normalize_record(record)
    return records


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    if not normalized.get("analysis_mode"):
        normalized["analysis_mode"] = "exact"
    normalized.setdefault("bounded_retry", False)
    normalized.setdefault("exact_timeout_seconds", None)
    normalized.setdefault("notes", None)
    return normalized


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_predictions_jsonl(path: Path, records: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for address in sorted(records):
            handle.write(json.dumps(records[address], ensure_ascii=False) + "\n")


def load_seed_addresses(path_text: str | None, disabled: bool) -> set[str]:
    if disabled or not path_text:
        return set()
    path = Path(path_text)
    if not path.exists():
        return set()
    if path.suffix.lower() == ".jsonl":
        return set(load_existing_records(path).keys())
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if "address" not in (reader.fieldnames or []):
            return set()
        return {row["address"].strip().lower() for row in reader if row.get("address")}


def build_command(
    job: ContractJob,
    temp_output_dir: Path,
    args: argparse.Namespace,
    *,
    bounded_retry: bool = False,
) -> list[str]:
    cmd = [
        args.python_exe,
        str(MAIN_SCRIPT),
        str(job.contract_path),
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
    if args.classic_fallback_policy:
        cmd.extend(["--classic-fallback-policy", args.classic_fallback_policy])
    if args.no_classic_fallback:
        cmd.append("--no-classic-fallback")
    if args.ablation_no_se_icfg_modeling_strict:
        cmd.append("--ablation-no-se-icfg-modeling-strict")
    if args.ablation_no_icfg_modeling:
        cmd.append("--ablation-no-icfg-modeling")
    if args.ablation_no_semantic_enhancement:
        cmd.append("--ablation-no-semantic-enhancement")
    if args.ablation_intra_contract_only:
        cmd.append("--ablation-intra-contract-only")
    if args.ablation_no_callback_edges:
        cmd.append("--ablation-no-callback-edges")
    if args.ablation_no_cross_contract_path_recovery:
        cmd.append("--ablation-no-cross-contract-path-recovery")
    if args.ablation_no_state_access_semantics:
        cmd.append("--ablation-no-state-access-semantics")
    if args.ablation_no_state_access_propagation:
        cmd.append("--ablation-no-state-access-propagation")
    if args.ablation_explicit_state_conflict_only:
        cmd.append("--ablation-explicit-state-conflict-only")
    if args.ablation_no_state_conflict:
        cmd.append("--ablation-no-state-conflict")
    if args.ablation_no_lock_context:
        cmd.append("--ablation-no-lock-context")
    if args.ablation_no_path_constraints:
        cmd.append("--ablation-no-path-constraints")
    if args.ablation_no_ror_mismatch_window:
        cmd.append("--ablation-no-ror-mismatch-window")
    if args.ablation_no_ror_propagation:
        cmd.append("--ablation-no-ror-propagation")
    if args.ablation_no_ror_sensitive_sink:
        cmd.append("--ablation-no-ror-sensitive-sink")
    use_bounded_ccr = args.bounded_ccr or bounded_retry
    if use_bounded_ccr:
        cmd.append("--bounded-ccr")
        if args.ccr_state_limit is not None:
            cmd.extend(["--ccr-state-limit", str(args.ccr_state_limit)])
        if args.ccr_time_budget is not None:
            cmd.extend(["--ccr-time-budget", str(args.ccr_time_budget)])
    return cmd


def run_detector_process(
    job: ContractJob,
    args: argparse.Namespace,
    temp_output_dir: Path,
    *,
    bounded_retry: bool = False,
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    cmd = build_command(job, temp_output_dir, args, bounded_retry=bounded_retry)
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=args.process_timeout,
            check=False,
        )
        return completed, None
    except subprocess.TimeoutExpired:
        return None, f"Process timeout after {args.process_timeout}s"


def record_from_report(
    job: ContractJob,
    args: argparse.Namespace,
    temp_output_dir: Path,
    final_report_dir: Path,
    report_data: dict[str, Any],
    runtime_seconds: float,
    *,
    analysis_mode: str,
    bounded_retry: bool,
    exact_timeout_seconds: float | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
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
        "address": job.address,
        "prediction": prediction,
        "status": "ok",
        "analysis_mode": analysis_mode,
        "bounded_retry": bounded_retry,
        "runtime_seconds": runtime_seconds,
        "exact_timeout_seconds": exact_timeout_seconds,
        "total_findings": total_findings,
        "classic_findings": classic_findings,
        "cross_contract_findings": cross_contract_findings,
        "ror_findings": ror_findings,
        "contract_path": display_path(job.contract_path),
        "report_dir": kept_report_dir,
        "error": None,
        "notes": notes,
    }


def evaluate_contract(
    job: ContractJob,
    args: argparse.Namespace,
    scratch_root: Path,
    reports_root: Path,
) -> dict[str, Any]:
    started = perf_counter()
    temp_output_dir = scratch_root / job.address
    final_report_dir = reports_root / job.address
    report_path = temp_output_dir / "vulnerabilities.json"
    clean_directory(temp_output_dir)
    existing_timeout_records = getattr(args, "existing_timeout_records", {}) or {}
    existing_timeout_record = existing_timeout_records.get(job.address)

    if (
        existing_timeout_record
        and args.retry_timeout_with_bounded_ccr
        and args.mode in {"full", "ccr"}
        and not args.bounded_ccr
    ):
        retry_started = perf_counter()
        completed, retry_timeout_error = run_detector_process(
            job,
            args,
            temp_output_dir,
            bounded_retry=True,
        )
        retry_runtime_seconds = round(perf_counter() - retry_started, 6)
        if not retry_timeout_error and report_path.exists() and completed is not None:
            try:
                retry_report_data = json.loads(report_path.read_text(encoding="utf-8"))
                return record_from_report(
                    job,
                    args,
                    temp_output_dir,
                    final_report_dir,
                    retry_report_data,
                    retry_runtime_seconds,
                    analysis_mode="bounded_retry",
                    bounded_retry=True,
                    exact_timeout_seconds=existing_timeout_record.get("runtime_seconds"),
                    notes=(
                        "Previous exact run timed out; existing timeout was rerun "
                        "directly with bounded CCR."
                    ),
                )
            except json.JSONDecodeError as exc:
                clean_directory(temp_output_dir)
                return {
                    "address": job.address,
                    "prediction": None,
                    "status": "invalid_report",
                    "analysis_mode": "bounded_retry",
                    "bounded_retry": True,
                    "runtime_seconds": retry_runtime_seconds,
                    "exact_timeout_seconds": existing_timeout_record.get("runtime_seconds"),
                    "total_findings": None,
                    "classic_findings": None,
                    "cross_contract_findings": None,
                    "ror_findings": None,
                    "contract_path": display_path(job.contract_path),
                    "report_dir": None,
                    "error": f"Invalid bounded retry JSON report: {exc}",
                    "notes": "Previous exact run timed out.",
                }
        clean_directory(temp_output_dir)
        return {
            "address": job.address,
            "prediction": None,
            "status": "timeout",
            "analysis_mode": "bounded_retry",
            "bounded_retry": True,
            "runtime_seconds": retry_runtime_seconds,
            "exact_timeout_seconds": existing_timeout_record.get("runtime_seconds"),
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "contract_path": display_path(job.contract_path),
            "report_dir": None,
            "error": retry_timeout_error or "Bounded CCR retry did not produce a JSON report",
            "notes": "Previous exact run timed out.",
        }

    if not job.contract_path.exists():
        return {
            "address": job.address,
            "prediction": None,
            "status": "missing_source",
            "analysis_mode": "exact",
            "bounded_retry": False,
            "runtime_seconds": round(perf_counter() - started, 6),
            "exact_timeout_seconds": None,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "contract_path": display_path(job.contract_path),
            "report_dir": None,
            "error": f"Missing source file: {job.contract_path}",
            "notes": None,
        }

    completed, timeout_error = run_detector_process(job, args, temp_output_dir)
    if timeout_error:
        exact_timeout_seconds = round(perf_counter() - started, 6)
        clean_directory(temp_output_dir)
        should_retry = (
            bool(args.retry_timeout_with_bounded_ccr)
            and args.mode in {"full", "ccr"}
            and not args.bounded_ccr
        )
        if should_retry:
            retry_started = perf_counter()
            completed, retry_timeout_error = run_detector_process(
                job,
                args,
                temp_output_dir,
                bounded_retry=True,
            )
            retry_runtime_seconds = round(perf_counter() - retry_started, 6)
            if not retry_timeout_error:
                retry_report_path = temp_output_dir / "vulnerabilities.json"
                if retry_report_path.exists() and completed is not None:
                    try:
                        retry_report_data = json.loads(retry_report_path.read_text(encoding="utf-8"))
                        return record_from_report(
                            job,
                            args,
                            temp_output_dir,
                            final_report_dir,
                            retry_report_data,
                            retry_runtime_seconds,
                            analysis_mode="bounded_retry",
                            bounded_retry=True,
                            exact_timeout_seconds=exact_timeout_seconds,
                            notes=(
                                f"Exact run timed out after {args.process_timeout}s; "
                                "bounded CCR retry completed."
                            ),
                        )
                    except json.JSONDecodeError as exc:
                        clean_directory(temp_output_dir)
                        return {
                            "address": job.address,
                            "prediction": None,
                            "status": "invalid_report",
                            "analysis_mode": "bounded_retry",
                            "bounded_retry": True,
                            "runtime_seconds": retry_runtime_seconds,
                            "exact_timeout_seconds": exact_timeout_seconds,
                            "total_findings": None,
                            "classic_findings": None,
                            "cross_contract_findings": None,
                            "ror_findings": None,
                            "contract_path": display_path(job.contract_path),
                            "report_dir": None,
                            "error": f"Invalid bounded retry JSON report: {exc}",
                            "notes": f"Exact run timed out after {args.process_timeout}s.",
                        }
            clean_directory(temp_output_dir)
            timeout_error = retry_timeout_error or "Bounded CCR retry did not produce a JSON report"

        return {
            "address": job.address,
            "prediction": None,
            "status": "timeout",
            "analysis_mode": "bounded_retry" if should_retry else "exact",
            "bounded_retry": bool(should_retry),
            "runtime_seconds": round(perf_counter() - started, 6),
            "exact_timeout_seconds": exact_timeout_seconds,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "contract_path": display_path(job.contract_path),
            "report_dir": None,
            "error": timeout_error,
            "notes": (
                f"Exact run timed out after {args.process_timeout}s."
                if should_retry
                else None
            ),
        }

    runtime_seconds = round(perf_counter() - started, 6)
    stdout_text = completed.stdout.strip() if completed else ""
    stderr_text = completed.stderr.strip() if completed else ""

    if not report_path.exists():
        clean_directory(temp_output_dir)
        return {
            "address": job.address,
            "prediction": None,
            "status": "analysis_failed",
            "analysis_mode": "exact",
            "bounded_retry": False,
            "runtime_seconds": runtime_seconds,
            "exact_timeout_seconds": None,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "contract_path": display_path(job.contract_path),
            "report_dir": None,
            "error": trim_error_text(stderr_text or stdout_text or f"Process exited with code {completed.returncode}"),
            "notes": None,
        }

    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        clean_directory(temp_output_dir)
        return {
            "address": job.address,
            "prediction": None,
            "status": "invalid_report",
            "analysis_mode": "exact",
            "bounded_retry": False,
            "runtime_seconds": runtime_seconds,
            "exact_timeout_seconds": None,
            "total_findings": None,
            "classic_findings": None,
            "cross_contract_findings": None,
            "ror_findings": None,
            "contract_path": display_path(job.contract_path),
            "report_dir": None,
            "error": f"Invalid JSON report: {exc}",
            "notes": None,
        }

    return record_from_report(
        job,
        args,
        temp_output_dir,
        final_report_dir,
        report_data,
        runtime_seconds,
        analysis_mode="bounded" if args.bounded_ccr else "exact",
        bounded_retry=False,
    )


def write_predictions_csv(path: Path, records: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RECORD_FIELDS)
        writer.writeheader()
        for address in sorted(records):
            record = records[address]
            writer.writerow({field: record.get(field) for field in RECORD_FIELDS})


def summarize_status(records: dict[str, dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for record in records.values():
        status = str(record.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def write_summary(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_batch_manifest(path: Path, jobs: list[ContractJob], records: dict[str, dict[str, Any]]) -> None:
    rows = []
    for job in jobs:
        record = records.get(job.address, {})
        rows.append(
            {
                "address": job.address,
                "status": record.get("status"),
                "analysis_mode": record.get("analysis_mode"),
                "prediction": record.get("prediction"),
                "total_findings": record.get("total_findings"),
                "runtime_seconds": record.get("runtime_seconds"),
                "contract_path": display_path(job.contract_path),
            }
        )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["address"])
        writer.writeheader()
        writer.writerows(rows)


def build_summary_payload(
    args: argparse.Namespace,
    jobs: list[ContractJob],
    seed_addresses: set[str],
    records: dict[str, dict[str, Any]],
    selected_batch: list[ContractJob],
) -> dict[str, Any]:
    all_addresses = {job.address for job in jobs}
    seed_in_dataset = seed_addresses & all_addresses
    completed_addresses = set(records)
    known_done = seed_in_dataset | completed_addresses
    remaining = len(all_addresses - known_done)
    ok_records = [record for record in records.values() if record.get("status") == "ok"]
    positive_records = [record for record in ok_records if record.get("prediction") == 1]
    bounded_retry_records = [
        record for record in ok_records if str(record.get("analysis_mode") or "") == "bounded_retry"
    ]
    runtimes = [
        float(record["runtime_seconds"])
        for record in ok_records
        if record.get("runtime_seconds") not in (None, "")
    ]
    return {
        "dataset_summary": {
            "contracts_total": len(jobs),
            "seed_predictions_skipped": len(seed_in_dataset),
            "completed_records_in_output": len(completed_addresses),
            "known_done_total": len(known_done),
            "remaining_after_this_run": remaining,
            "output_dir": display_path(Path(args.output_dir)),
            "predictions_jsonl": display_path(Path(args.output_dir) / "predictions.jsonl"),
            "predictions_csv": display_path(Path(args.output_dir) / "predictions.csv"),
        },
        "batch_summary": {
            "selected_count": len(selected_batch),
            "first_address": selected_batch[0].address if selected_batch else None,
            "last_address": selected_batch[-1].address if selected_batch else None,
            "batch_size": args.batch_size,
            "workers": args.workers,
            "skip_run": bool(args.skip_run),
            "dry_run": bool(args.dry_run),
        },
        "status_summary": summarize_status(records),
        "finding_summary": {
            "ok_records": len(ok_records),
            "positive_predictions": len(positive_records),
            "bounded_retry_ok_records": len(bounded_retry_records),
            "avg_ok_runtime_seconds": (sum(runtimes) / len(runtimes) if runtimes else None),
        },
        "run_config": {
            "mode": args.mode,
            "report_mode": args.report_mode,
            "analysis_timeout": args.analysis_timeout,
            "process_timeout": args.process_timeout,
            "precision_filter": not args.no_precision_filter,
            "ablation_no_icfg_modeling": bool(args.ablation_no_icfg_modeling),
            "ablation_no_se_icfg_modeling_strict": bool(args.ablation_no_se_icfg_modeling_strict),
            "ablation_no_semantic_enhancement": bool(args.ablation_no_semantic_enhancement),
            "ablation_intra_contract_only": bool(args.ablation_intra_contract_only),
            "ablation_no_state_access_semantics": bool(args.ablation_no_state_access_semantics),
            "ablation_no_state_access_propagation": bool(args.ablation_no_state_access_propagation),
            "ablation_explicit_state_conflict_only": bool(args.ablation_explicit_state_conflict_only),
            "bounded_ccr": bool(args.bounded_ccr),
            "ccr_state_limit": args.ccr_state_limit,
            "ccr_time_budget": args.ccr_time_budget,
            "retry_timeout_with_bounded_ccr": bool(args.retry_timeout_with_bounded_ccr),
            "retry_existing_timeouts": bool(args.retry_existing_timeouts),
            "retry_existing_failures": bool(args.retry_existing_failures),
            "seed_predictions": None if args.no_skip_seed_predictions else args.skip_seed_predictions,
            "python_exe": args.python_exe,
        },
    }


def main() -> int:
    args = parse_args()
    if args.batch_size <= 0:
        print("--batch-size must be positive.")
        return 2

    contracts_dir = Path(args.contracts_dir)
    output_dir = Path(args.output_dir).resolve()
    args.output_dir = str(output_dir)
    scratch_root = output_dir / "_tmp"
    reports_root = output_dir / "reports"
    predictions_jsonl = output_dir / "predictions.jsonl"
    predictions_csv = output_dir / "predictions.csv"
    summary_json = output_dir / "summary.json"
    batch_manifest_csv = output_dir / "last_batch.csv"

    if not contracts_dir.exists():
        print(f"Contracts directory does not exist: {contracts_dir}")
        return 1
    if not Path(args.python_exe).exists():
        print(f"Python executable does not exist: {args.python_exe}")
        return 1

    if args.force and not args.skip_run and not args.dry_run:
        if predictions_jsonl.exists():
            predictions_jsonl.unlink()
        clean_directory(scratch_root)
        clean_directory(reports_root)

    address_filter = load_address_filter(args.addresses_file)
    jobs = iter_contract_jobs(contracts_dir, address_filter, args.start_after)
    if not jobs:
        print("No contracts selected.")
        return 1

    seed_addresses = load_seed_addresses(args.skip_seed_predictions, args.no_skip_seed_predictions)
    records = load_existing_records(predictions_jsonl)
    rerunnable_timeouts = {
        address
        for address, record in records.items()
        if args.retry_existing_timeouts and record.get("status") == "timeout"
    }
    rerunnable_failures = {
        address
        for address, record in records.items()
        if args.retry_existing_failures and record.get("status") == "analysis_failed"
    }
    args.existing_timeout_records = {
        address: records[address]
        for address in rerunnable_timeouts
        if address in records
    }
    done_addresses = (
        set(records)
        - rerunnable_timeouts
        - rerunnable_failures
    ) | (seed_addresses & {job.address for job in jobs})
    to_run = [job for job in jobs if job.address not in done_addresses]
    selected_batch = to_run[: args.batch_size]

    print(f"Contracts selected: {len(jobs)}")
    print(f"Already skipped from seed predictions: {len(seed_addresses & {job.address for job in jobs})}")
    print(f"Already completed in this output: {len(records)}")
    print(f"Remaining before this run: {len(to_run)}")
    print(f"Selected batch size: {len(selected_batch)}")
    if selected_batch:
        print(f"Batch range: {selected_batch[0].address} -> {selected_batch[-1].address}")

    output_dir.mkdir(parents=True, exist_ok=True)
    if args.dry_run or args.skip_run or not selected_batch:
        write_predictions_jsonl(predictions_jsonl, records)
        write_predictions_csv(predictions_csv, records)
        write_batch_manifest(batch_manifest_csv, selected_batch, records)
        write_summary(summary_json, build_summary_payload(args, jobs, seed_addresses, records, selected_batch))
        if args.dry_run:
            print("Dry run only; no analysis executed.")
        elif args.skip_run:
            print("Skip-run requested; regenerated cached artifacts only.")
        else:
            print("No remaining contracts to run.")
        return 0

    scratch_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(evaluate_contract, job, args, scratch_root, reports_root): job
            for job in selected_batch
        }
        completed = 0
        total = len(futures)
        for future in as_completed(futures):
            job = futures[future]
            try:
                record = future.result()
            except Exception as exc:  # Defensive guard so one worker cannot lose batch progress.
                record = {
                    "address": job.address,
                    "prediction": None,
                    "status": "runner_failed",
                    "analysis_mode": "runner",
                    "bounded_retry": False,
                    "runtime_seconds": None,
                    "exact_timeout_seconds": None,
                    "total_findings": None,
                    "classic_findings": None,
                    "cross_contract_findings": None,
                    "ror_findings": None,
                    "contract_path": display_path(job.contract_path),
                    "report_dir": None,
                    "error": trim_error_text(str(exc)),
                    "notes": None,
                }
            records[record["address"]] = record
            append_jsonl(predictions_jsonl, record)
            completed += 1
            print(
                f"[{completed}/{total}] {record['address']} -> "
                f"status={record['status']}, prediction={record['prediction']}, "
                f"findings={record['total_findings']}"
            )

    write_predictions_jsonl(predictions_jsonl, records)
    write_predictions_csv(predictions_csv, records)
    write_batch_manifest(batch_manifest_csv, selected_batch, records)
    write_summary(summary_json, build_summary_payload(args, jobs, seed_addresses, records, selected_batch))

    print("\nArtifacts written:")
    print(f"- Predictions JSONL: {predictions_jsonl}")
    print(f"- Predictions CSV:   {predictions_csv}")
    print(f"- Last batch CSV:    {batch_manifest_csv}")
    print(f"- Summary JSON:      {summary_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
