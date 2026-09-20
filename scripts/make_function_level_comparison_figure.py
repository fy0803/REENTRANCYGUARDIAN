from pathlib import Path
import csv

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["font.size"] = 7.5
plt.rcParams["axes.spines.right"] = False
plt.rcParams["axes.spines.top"] = False
plt.rcParams["axes.linewidth"] = 0.8
plt.rcParams["legend.frameon"] = False


OUT_DIR = Path("figures/function_level_comparison")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATA = [
    {"tool": "Our method", "tp": 157, "fp": 94, "fn": 70, "tn": 425},
    {"tool": "Slither", "tp": 225, "fp": 328, "fn": 2, "tn": 191},
    {"tool": "Mythril", "tp": 66, "fp": 75, "fn": 99, "tn": 315},
    {"tool": "Sailfish", "tp": 18, "fp": 8, "fn": 134, "tn": 350},
    {"tool": "SliSE", "tp": 34, "fp": 70, "fn": 193, "tn": 449},
]


def build_source_data() -> list[dict]:
    rows = []
    for row in DATA:
        tp, fp, fn, tn = row["tp"], row["fp"], row["fn"], row["tn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        rows.append(
            {
                **row,
                "n_outcome_sum": tp + fp + fn + tn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "fp_plus_fn": fp + fn,
            }
        )
    return rows


def add_panel_label(ax, label):
    ax.text(
        -0.08,
        1.04,
        label,
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        fontsize=9,
        fontweight="bold",
    )


def main() -> None:
    rows = build_source_data()
    with (OUT_DIR / "source_data_function_level_comparison.csv").open(
        "w", newline="", encoding="utf-8"
    ) as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    methods = [row["tool"] for row in rows]
    metrics = ["precision", "recall", "f1"]
    metric_labels = ["Precision", "Recall", "F1"]

    colors = {
        "Our method": "#B64342",
        "Slither": "#0F4D92",
        "Mythril": "#7A7A7A",
        "Sailfish": "#A8A8A8",
        "SliSE": "#4D4D4D",
    }

    fig = plt.figure(figsize=(7.1, 3.75), constrained_layout=False)
    gs = fig.add_gridspec(1, 2, width_ratios=[1.25, 1.0], wspace=0.34)
    ax_a = fig.add_subplot(gs[0, 0])
    ax_b = fig.add_subplot(gs[0, 1])

    x = np.arange(len(metrics))
    label_offsets = {
        "Our method": 0.008,
        "Slither": -0.012,
        "Mythril": 0.016,
        "Sailfish": -0.016,
        "SliSE": 0.016,
    }
    for row in rows:
        tool = row["tool"]
        y = [row[m] for m in metrics]
        lw = 2.2 if tool == "Our method" else 1.1
        alpha = 1.0 if tool in {"Our method", "Slither"} else 0.7
        z = 4 if tool == "Our method" else 3
        ax_a.plot(
            x,
            y,
            marker="o",
            markersize=5.2 if tool == "Our method" else 4.0,
            linewidth=lw,
            color=colors[tool],
            alpha=alpha,
            label=tool,
            zorder=z,
        )
        ax_a.text(
            x[-1] + 0.08,
            y[-1] + label_offsets[tool],
            tool,
            va="center",
            ha="left",
            fontsize=6.8,
            color=colors[tool],
        )

    ax_a.set_xticks(x)
    ax_a.set_xticklabels(metric_labels)
    ax_a.set_xlim(-0.10, 2.70)
    ax_a.set_ylim(0, 1.04)
    ax_a.set_ylabel("Score")
    ax_a.set_title("Function-level detection profile", loc="left", fontsize=8.5, pad=7)
    ax_a.grid(axis="y", color="#E5E5E5", linewidth=0.7)
    ax_a.axhline(0.5, color="#BDBDBD", linewidth=0.7, linestyle="--", zorder=0)
    add_panel_label(ax_a, "a")

    y_pos = np.arange(len(methods))
    fp = np.array([row["fp"] for row in rows])
    fn = np.array([row["fn"] for row in rows])
    ax_b.barh(
        y_pos,
        fp,
        color="#E9A6A1",
        edgecolor="white",
        linewidth=0.5,
        label="FP",
    )
    ax_b.barh(
        y_pos,
        fn,
        left=fp,
        color="#B4C0E4",
        edgecolor="white",
        linewidth=0.5,
        label="FN",
    )
    ax_b.set_yticks(y_pos)
    ax_b.set_yticklabels(methods)
    ax_b.invert_yaxis()
    ax_b.set_xlabel("Count")
    ax_b.set_title("Error burden", loc="left", fontsize=8.5, pad=7)
    ax_b.grid(axis="x", color="#E5E5E5", linewidth=0.7)
    ax_b.legend(loc="lower right", ncol=2, fontsize=6.8)

    for i, row in enumerate(rows):
        total_error = int(row["fp_plus_fn"])
        ax_b.text(
            total_error + 7,
            i,
            str(total_error),
            va="center",
            ha="left",
            fontsize=6.8,
            color="#4D4D4D",
        )

    ax_b.set_xlim(0, max(row["fp_plus_fn"] for row in rows) + 55)
    add_panel_label(ax_b, "b")

    note = (
        "Source data: function-level benchmark. Metrics recomputed from TP, FP, FN and TN "
        "in the supplied table."
    )
    fig.text(0.01, 0.01, note, ha="left", va="bottom", fontsize=6.2, color="#606060")

    for suffix, kwargs in {
        "svg": {},
        "pdf": {},
        "tiff": {"dpi": 600},
        "png": {"dpi": 300},
    }.items():
        fig.savefig(
            OUT_DIR / f"function_level_tool_comparison.{suffix}",
            bbox_inches="tight",
            **kwargs,
        )

    plt.close(fig)


if __name__ == "__main__":
    main()
