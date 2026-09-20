from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "results" / "figures" / "three_tool_ror_benchmark_source.csv"
OUT_DIR = ROOT / "results" / "figures"
OUT_STEM = OUT_DIR / "three_tool_ror_benchmark"


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def as_float(row: dict[str, str], key: str) -> float:
    return float(row[key])


def as_int(row: dict[str, str], key: str) -> int:
    return int(float(row[key]))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = load_rows(DATA_PATH)
    tools = ["RG", "Slither", "SliSE*"]

    plt.rcParams.update(
        {
            "font.family": "Arial",
            "font.sans-serif": ["Arial", "DejaVu Sans", "Liberation Sans"],
            "font.size": 7.5,
            "axes.titlesize": 8.2,
            "axes.labelsize": 7.5,
            "xtick.labelsize": 7.0,
            "ytick.labelsize": 7.0,
            "legend.fontsize": 7.0,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "axes.linewidth": 0.7,
        }
    )

    fig, (ax_counts, ax_metrics) = plt.subplots(
        1,
        2,
        figsize=(7.2, 3.9),
        gridspec_kw={"width_ratios": [1.22, 1.0], "wspace": 0.34},
        constrained_layout=False,
    )
    fig.patch.set_facecolor("white")

    categories = [
        ("tp", "Correct\nlocation", "#3F8F64"),
        ("fp", "Incorrect\nreport", "#C95454"),
        ("fn_no_report", "Missed ROR\n(no report)", "#D99A2B"),
        ("tn", "Correct Safe\n(no report)", "#AEB8C2"),
    ]

    y_positions = list(range(len(rows)))
    left = [0] * len(rows)
    for key, label, color in categories:
        values = [as_int(row, key) for row in rows]
        bars = ax_counts.barh(
            y_positions,
            values,
            left=left,
            height=0.54,
            label=label,
            color=color,
            edgecolor="white",
            linewidth=0.6,
        )
        for bar, value in zip(bars, values):
            if value >= 8:
                ax_counts.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    str(value),
                    ha="center",
                    va="center",
                    color="white" if key in {"tp", "fp"} else "#1F2933",
                    fontsize=7.0,
                    fontweight="bold",
                )
            elif value > 0:
                ax_counts.text(
                    bar.get_x() + bar.get_width() + 1.0,
                    bar.get_y() + bar.get_height() / 2,
                    str(value),
                    ha="left",
                    va="center",
                    color="#1F2933",
                    fontsize=7.0,
                )
        left = [base + value for base, value in zip(left, values)]

    ax_counts.set_yticks(y_positions, tools)
    ax_counts.invert_yaxis()
    ax_counts.set_xlim(0, 136)
    ax_counts.set_title("Sample disposition")
    ax_counts.xaxis.set_major_locator(mticker.MultipleLocator(34))
    ax_counts.grid(axis="x", color="#D6DCE2", linewidth=0.55)
    ax_counts.set_axisbelow(True)
    ax_counts.spines["top"].set_visible(False)
    ax_counts.spines["right"].set_visible(False)
    ax_counts.spines["left"].set_visible(False)
    ax_counts.tick_params(axis="y", length=0)
    ax_counts.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, -0.46),
        ncol=2,
        frameon=False,
        handlelength=1.4,
        columnspacing=1.6,
    )

    metric_names = ["Precision", "Recall", "F1"]
    metric_keys = ["precision", "recall", "f1"]
    metric_colors = ["#2F5D8C", "#4F8E9E", "#6C6A9A"]
    x_positions = list(range(len(rows)))
    width = 0.22
    offsets = [-width, 0, width]
    for metric, key, color, offset in zip(metric_names, metric_keys, metric_colors, offsets):
        values = [as_float(row, key) * 100.0 for row in rows]
        bars = ax_metrics.bar(
            [x + offset for x in x_positions],
            values,
            width=width,
            color=color,
            label=metric,
            edgecolor="white",
            linewidth=0.5,
        )
        for bar, value in zip(bars, values):
            ax_metrics.text(
                bar.get_x() + bar.get_width() / 2,
                value + 2.0,
                f"{value:.0f}",
                ha="center",
                va="bottom",
                fontsize=6.6,
                color="#26323F",
            )

    ax_metrics.set_xticks(x_positions, tools)
    ax_metrics.set_ylim(0, 108)
    ax_metrics.set_ylabel("Score (%)")
    ax_metrics.set_title("Location-level performance")
    ax_metrics.yaxis.set_major_locator(mticker.MultipleLocator(25))
    ax_metrics.grid(axis="y", color="#D6DCE2", linewidth=0.55)
    ax_metrics.set_axisbelow(True)
    ax_metrics.spines["top"].set_visible(False)
    ax_metrics.spines["right"].set_visible(False)
    ax_metrics.legend(loc="upper right", frameon=False, handlelength=1.4)

    ax_counts.text(-0.14, 1.04, "a", transform=ax_counts.transAxes, fontsize=10, fontweight="bold")
    ax_metrics.text(-0.16, 1.04, "b", transform=ax_metrics.transAxes, fontsize=10, fontweight="bold")

    fig.text(
        0.02,
        0.047,
        "Benchmark: 136 samples (78 ROR, 58 Safe). Slither incorrect reports include 6 ROR files with wrong vulnerability locations; recall uses TP/78.",
        ha="left",
        va="bottom",
        fontsize=6.35,
        color="#4B5563",
    )
    fig.text(
        0.02,
        0.023,
        "*SliSE is aggregate-only; TP is a best-case assumption from 4 reported positives.",
        ha="left",
        va="bottom",
        fontsize=6.35,
        color="#4B5563",
    )
    fig.subplots_adjust(left=0.08, right=0.985, top=0.86, bottom=0.36)

    for suffix in ("svg", "pdf", "png", "tiff"):
        path = OUT_STEM.with_suffix(f".{suffix}")
        if suffix in {"png", "tiff"}:
            fig.savefig(path, dpi=600, facecolor="white")
        else:
            fig.savefig(path, facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    main()
