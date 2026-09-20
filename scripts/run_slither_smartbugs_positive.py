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

from parser.slither_loader import SlitherLoader


DEFAULT_INPUT_DIR = ROOT / "datasets" / "smartbugs-curated" / "dataset" / "reentrancy"
DEFAULT_VERSIONS_CSV = ROOT / "datasets" / "smartbugs-curated" / "versions.csv"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "slither_smartbugs_positive"
SLITHER_DETECTORS = ",".join(
    [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-events",
        "reentrancy-unlimited-gas",
    ]
)


@dataclass(frozen=True)
class PositiveCase:
    case_id: str
    contract_path: Path
    dataset_path: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Slither's reentrancy detectors on the SmartBugs Curated positive reentrancy set."
    )
    parser.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR), help="Path to dataset/reentrancy.")
    parser.add_argument("--versions-csv", default=str(DEFAULT_VERSIONS_CSV), help="Path to SmartBugs versions.csv.")
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run only this case id.")
    parser.add_argument("--limit", type=int, help="Maximum number of samples to evaluate.")
    parser.add_argument("--process-timeout", type=int, default=300, help="Hard timeout per Slither run.")
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(2, os.cpu_count() or 1)),
        help="Number of parallel Slither processes.",
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


def slither_executable() -> str:
    suffix = ".exe" if os.name == "nt" else ""
    candidate = Path(sys.executable).parent / f"slither{suffix}"
    return str(candidate) if candidate.exists() else "slither"


def collect_cases(input_dir: Path, selected_cases: Optional[set[str]], limit: Optional[int]) -> list[PositiveCase]:
    cases: list[PositiveCase] = []
    for contract_path in sorted(input_dir.glob("*.sol"), key=lambda path: path.name.lower()):
        case_id = contract_path.stem
        if selected_cases and case_id not in selected_cases:
            continue
        dataset_path = f"dataset/reentrancy/{contract_path.name}"
        cases.append(PositiveCase(case_id=case_id, contract_path=contract_path, dataset_path=dataset_path))

    missing = sorted((selected_cases or set()) - {case.case_id for case in cases})
    if missing:
        raise SystemExit(f"Unknown positive case ids: {', '.join(missing)}")

    if limit is not None:
        cases = cases[:limit]
    return cases


def load_versions(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {row["file"].replace("\\", "/"): row for row in csv.DictReader(handle)}


def resolve_solc(case: PositiveCase, versions: dict[str, dict[str, str]], loader: SlitherLoader) -> tuple[Optional[str], Optional[str], str]:
    version_row = versions.get(case.dataset_path.replace("\\", "/"))
    compiled_version = (version_row or {}).get("compiled version", "").strip()
    if compiled_version:
        exact_binary = loader._find_solc_binary(compiled_version)
        if exact_binary:
            return exact_binary, compiled_version, "versions_csv"

    binary = loader._resolve_solc_binary(str(case.contract_path))
    if binary:
        version = Path(binary).name.replace("solc-", "").replace(".exe", "")
        return binary, version, "pragma_fallback"

    return None, None, "not_found"


def build_command(case: PositiveCase, report_json: Path, solc_binary: Optional[str]) -> list[str]:
    cmd = [
        slither_executable(),
        str(case.contract_path),
        "--detect",
        SLITHER_DETECTORS,
        "--json",
        str(report_json),
    ]
    if solc_binary:
        cmd.extend(["--solc", solc_binary])
    return cmd


def parse_slither_report(path: Path) -> tuple[bool, Optional[str], list[dict[str, Any]]]:
    if not path.exists():
        return False, "missing_json_report", []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"invalid_json: {exc}", []

    if not data.get("success"):
        return False, str(data.get("error") or "slither_json_success_false"), []
    detectors = list((data.get("results") or {}).get("detectors") or [])
    return True, None, detectors


def evaluate_case(
    case: PositiveCase,
    args: argparse.Namespace,
    output_dir: Path,
    versions: dict[str, dict[str, str]],
) -> dict[str, Any]:
    report_dir = output_dir / "reports" / case.case_id
    record_path = output_dir / "records" / f"{case.case_id}.json"
    if record_path.exists() and not args.force:
        return json.loads(record_path.read_text(encoding="utf-8"))

    report_dir.parent.mkdir(parents=True, exist_ok=True)
    record_path.parent.mkdir(parents=True, exist_ok=True)
    if report_dir.exists():
        safe_remove_tree(report_dir, output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    loader = SlitherLoader()
    solc_binary, solc_version, solc_source = resolve_solc(case, versions, loader)
    report_json = report_dir / "slither.json"
    raw_log = report_dir / "raw.log"
    cmd = build_command(case, report_json, solc_binary)

    started = perf_counter()
    status = "ok"
    error: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    detectors: list[dict[str, Any]] = []

    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=args.process_timeout,
            check=False,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        stdout = completed.stdout
        stderr = completed.stderr
        raw_log.write_text((stdout or "") + ("\n" + stderr if stderr else ""), encoding="utf-8")

        success, json_error, detectors = parse_slither_report(report_json)
        if not success:
            status = "analysis_failed"
            error = trim_text(json_error or (stdout or "") + "\n" + (stderr or ""))
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout = exc.stdout if isinstance(exc.stdout, str) else None
        stderr = exc.stderr if isinstance(exc.stderr, str) else None
        raw_log.write_text((stdout or "") + ("\n" + stderr if stderr else ""), encoding="utf-8")
        error = f"Process timeout after {args.process_timeout}s"

    runtime_seconds = perf_counter() - started
    detector_counts: dict[str, int] = {}
    for detector in detectors:
        check = str(detector.get("check") or "unknown")
        detector_counts[check] = detector_counts.get(check, 0) + 1

    finding_count = len(detectors)
    detected = status == "ok" and finding_count > 0
    record = {
        "case_id": case.case_id,
        "input_path": display_path(case.contract_path),
        "status": status,
        "detected": int(detected),
        "finding_count": finding_count,
        "detectors": "; ".join(f"{key}:{value}" for key, value in sorted(detector_counts.items())),
        "solc_version": solc_version,
        "solc_source": solc_source,
        "runtime_seconds": runtime_seconds,
        "report_dir": display_path(report_dir),
        "raw_log": display_path(raw_log),
        "error": error,
        "stdout": trim_text(stdout),
        "stderr": trim_text(stderr),
    }
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return record


def write_predictions_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "input_path",
        "status",
        "detected",
        "finding_count",
        "detectors",
        "solc_version",
        "solc_source",
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
    detected_cases = sum(int(record["detected"]) for record in records)
    missed_cases = sum(1 for record in records if record["status"] == "ok" and not int(record["detected"]))
    failed_cases = sum(1 for record in records if record["status"] == "analysis_failed")
    timeout_cases = sum(1 for record in records if record["status"] == "timeout")
    avg_runtime = (
        sum(float(record["runtime_seconds"]) for record in records if record["status"] == "ok") / ok_cases
        if ok_cases
        else None
    )
    return {
        "tool": "Slither",
        "detectors": SLITHER_DETECTORS,
        "total_cases": total_cases,
        "ok_cases": ok_cases,
        "detected_cases": detected_cases,
        "missed_cases": missed_cases,
        "analysis_failed_cases": failed_cases,
        "timeout_cases": timeout_cases,
        "total_findings": sum(int(record["finding_count"]) for record in records),
        "recall_analyzed": detected_cases / ok_cases if ok_cases else None,
        "recall_all": detected_cases / total_cases if total_cases else None,
        "avg_runtime_seconds": avg_runtime,
        "status_summary": {
            status: sum(1 for record in records if record["status"] == status)
            for status in sorted({str(record["status"]) for record in records})
        },
    }


def format_rate(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def write_summary_markdown(path: Path, summary: dict[str, Any], records: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    lines.append("# Slither SmartBugs Positive Evaluation")
    lines.append("")
    lines.append("- Dataset: `datasets/smartbugs-curated/dataset/reentrancy`")
    lines.append(f"- Detectors: `{summary['detectors']}`")
    lines.append("- Metric note: this positive-only subset supports recall/detection rate, not precision.")
    lines.append("")
    lines.append("## Main Table")
    lines.append("")
    lines.append("| Tool | Cases | Analyzed | Detected | Missed | Failed | Timeout | Recall (Analyzed) | Recall (All) | Avg Runtime (s) | Findings |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        "| `{tool}` | {total_cases} | {ok_cases} | {detected_cases} | {missed_cases} | "
        "{analysis_failed_cases} | {timeout_cases} | {recall_analyzed} | {recall_all} | "
        "{avg_runtime_seconds} | {total_findings} |".format(
            **{
                **summary,
                "recall_analyzed": format_rate(summary["recall_analyzed"]),
                "recall_all": format_rate(summary["recall_all"]),
                "avg_runtime_seconds": format_rate(summary["avg_runtime_seconds"]),
            }
        )
    )
    lines.append("")
    lines.append("## Per-Case Results")
    lines.append("")
    lines.append("| Case | Status | Detected | Findings | Detectors | Solc | Runtime (s) |")
    lines.append("| --- | --- | ---: | ---: | --- | --- | ---: |")
    for record in records:
        lines.append(
            f"| `{record['case_id']}` | `{record['status']}` | {record['detected']} | "
            f"{record['finding_count']} | {record['detectors'] or 'None'} | "
            f"`{record['solc_version'] or 'N/A'}` | {float(record['runtime_seconds']):.3f} |"
        )

    non_ok = [record for record in records if record["status"] != "ok"]
    if non_ok:
        lines.append("")
        lines.append("## Non-Analyzed Cases")
        lines.append("")
        lines.append("| Case | Status | Error |")
        lines.append("| --- | --- | --- |")
        for record in non_ok:
            error = (record.get("error") or "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{record['case_id']}` | `{record['status']}` | {error} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex_table(path: Path, summary: dict[str, Any]) -> None:
    table = rf"""\begin{{table}}[t]
\centering
\caption{{Slither results on the SmartBugs reentrancy subset.}}
\label{{tab:slither-smartbugs-positive}}
\begin{{tabular}}{{lrrrrrrrr}}
\toprule
Tool & Cases & Analyzed & Detected & Missed & Failed & Timeout & Recall$_{{analyzed}}$ & Recall$_{{all}}$ \\
\midrule
Slither & {summary['total_cases']} & {summary['ok_cases']} & {summary['detected_cases']} & {summary['missed_cases']} & {summary['analysis_failed_cases']} & {summary['timeout_cases']} & {format_rate(summary['recall_analyzed'])} & {format_rate(summary['recall_all'])} \\
\bottomrule
\end{{tabular}}
\end{{table}}
"""
    path.write_text(table, encoding="utf-8")


def write_paper_text(path: Path, summary: dict[str, Any]) -> None:
    text = (
        "We also evaluated Slither's built-in reentrancy detectors on the SmartBugs reentrancy subset. "
        f"Slither successfully analyzed {summary['ok_cases']} out of {summary['total_cases']} contracts and "
        f"reported at least one reentrancy warning for {summary['detected_cases']} cases. This corresponds to "
        f"an analyzed-case recall of {format_rate(summary['recall_analyzed'])} and an end-to-end recall of "
        f"{format_rate(summary['recall_all'])}. Slither produced {summary['total_findings']} reentrancy findings "
        f"in total, with an average runtime of {format_rate(summary['avg_runtime_seconds'])} seconds per analyzed case.\n"
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cases = collect_cases(input_dir, set(args.selected_cases) if args.selected_cases else None, args.limit)
    if not cases:
        raise SystemExit(f"No Solidity files found under {input_dir}")
    versions = load_versions(Path(args.versions_csv))

    print(f"Selected {len(cases)} SmartBugs reentrancy positive cases.")
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(evaluate_case, case, args, output_dir, versions): case for case in cases}
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
                    "finding_count": 0,
                    "detectors": "",
                    "solc_version": None,
                    "solc_source": None,
                    "runtime_seconds": 0.0,
                    "report_dir": "",
                    "raw_log": "",
                    "error": str(exc),
                }
            records.append(record)
            print(
                f"[{index}/{len(cases)}] {case.case_id} -> status={record['status']}, "
                f"detected={record['detected']}, findings={record['finding_count']}, solc={record['solc_version']}"
            )

    records.sort(key=lambda record: record["case_id"])
    summary = compute_summary(records)
    (output_dir / "summary.json").write_text(
        json.dumps({"summary": summary, "records": records}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_predictions_csv(output_dir / "slither_positive_predictions.csv", records)
    write_summary_markdown(output_dir / "paper_results.md", summary, records)
    write_latex_table(output_dir / "paper_table.tex", summary)
    write_paper_text(output_dir / "paper_paragraph.md", summary)

    print("\nArtifacts written:")
    print(f"- Summary JSON: {output_dir / 'summary.json'}")
    print(f"- Predictions CSV: {output_dir / 'slither_positive_predictions.csv'}")
    print(f"- Paper results MD: {output_dir / 'paper_results.md'}")
    print(f"- LaTeX table: {output_dir / 'paper_table.tex'}")
    print(f"- Paper paragraph: {output_dir / 'paper_paragraph.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
