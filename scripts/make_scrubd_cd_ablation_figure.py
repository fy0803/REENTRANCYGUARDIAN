#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

import os

os.environ.setdefault("MPLCONFIGDIR", str(Path("results/paper_figures/.matplotlib_cache").resolve()))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import csv


OUT_DIR = Path("results/paper_figures/scrubd_cd_ablation")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATA = [
    {
        "variant": "Full",
        "short": "Full",
        "TP": 127,
        "FP": 57,
        "TN": 462,
        "FN": 100,
        "Precision": 69.02,
        "Recall": 55.95,
        "F1": 61.80,
    },
    {
        "variant": "w/o callback-entry compensation\nand loose conflict recovery",
        "short": "w/o callback\n+ loose conflict",
        "TP": 71,
        "FP": 46,
        "TN": 473,
        "FN": 156,
        "Precision": 60.68,
        "Recall": 31.28,
        "F1": 41.28,
    },
    {
        "variant": "w/o state-access semantics",
        "short": "w/o state\naccess semantics",
        "TP": 14,
        "FP": 10,
        "TN": 509,
        "FN": 213,
        "Precision": 58.33,
        "Recall": 6.17,
        "F1": 11.16,
    },
]


def apply_style() -> None:
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
    plt.rcParams["svg.fonttype"] = "none"
    plt.rcParams["pdf.fonttype"] = 42
    plt.rcParams["font.size"] = 7.5
    plt.rcParams["axes.spines.right"] = False
    plt.rcParams["axes.spines.top"] = False
    plt.rcParams["axes.linewidth"] = 0.8
    plt.rcParams["legend.frameon"] = False
    plt.rcParams["xtick.major.width"] = 0.7
    plt.rcParams["ytick.major.width"] = 0.7


def add_panel_label(ax, label: str) -> None:
    ax.text(
        -0.10,
        1.05,
        label,
        transform=ax.transAxes,
        fontsize=9,
        fontweight="bold",
        ha="left",
        va="bottom",
    )


def main() -> None:
    apply_style()
    with (OUT_DIR / "source_data_scrubd_cd_ablation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(DATA[0].keys()))
        writer.writeheader()
        writer.writerows(DATA)

    colors = {
        "TP": "#0F4D92",
        "FN": "#E9A6A1",
        "FP": "#8A8A8A",
        "Precision": "#4D4D4D",
        "Recall": "#0F4D92",
        "F1": "#B64342",
    }

    fig = plt.figure(figsize=(7.05, 3.65), constrained_layout=False)
    gs = fig.add_gridspec(
        1,
        2,
        width_ratios=[1.18, 1.0],
        left=0.075,
        right=0.985,
        bottom=0.18,
        top=0.84,
        wspace=0.36,
    )
    ax_counts = fig.add_subplot(gs[0, 0])
    ax_metrics = fig.add_subplot(gs[0, 1])

    fig.suptitle(
        "Ablation analysis on SCRUBD-CD function-level reentrancy detection",
        x=0.075,
        y=0.965,
        ha="left",
        fontsize=9,
        fontweight="bold",
    )
    fig.text(
        0.075,
        0.905,
        "Removing callback recovery and state-access semantics primarily reduces true-positive recovery.",
        ha="left",
        va="center",
        fontsize=7.5,
        color="#4D4D4D",
    )

    # Panel a: counts that explain the recall loss.
    y = np.arange(len(DATA))[::-1]
    h = 0.22
    tp = [row["TP"] for row in DATA]
    fn = [row["FN"] for row in DATA]
    fp = [row["FP"] for row in DATA]
    ax_counts.barh(y + h, tp, height=h, color=colors["TP"], label="TP")
    ax_counts.barh(y, fn, height=h, color=colors["FN"], label="FN")
    ax_counts.barh(y - h, fp, height=h, color=colors["FP"], label="FP")

    for yi, row in zip(y, DATA):
        for off, value, color in [
            (h, row["TP"], colors["TP"]),
            (0, row["FN"], colors["FN"]),
            (-h, row["FP"], colors["FP"]),
        ]:
            ax_counts.text(
                value + 4,
                yi + off,
                f"{value}",
                va="center",
                ha="left",
                fontsize=6.8,
                color=color,
            )

    ax_counts.set_yticks(y)
    ax_counts.set_yticklabels([row["short"] for row in DATA])
    ax_counts.set_xlabel("Function-level count")
    ax_counts.set_xlim(0, 235)
    ax_counts.set_xticks([0, 50, 100, 150, 200])
    ax_counts.tick_params(axis="y", length=0)
    ax_counts.legend(
        loc="lower right",
        ncol=3,
        handlelength=1.2,
        columnspacing=0.9,
        borderaxespad=0.1,
    )
    add_panel_label(ax_counts, "a")
    ax_counts.set_title("Detection outcomes", loc="left", fontsize=8, pad=6)

    # Panel b: metrics as a compact lollipop chart.
    metrics = ["Precision", "Recall", "F1"]
    x = np.arange(len(metrics))
    offsets = [0.18, 0.0, -0.18]
    marker_styles = ["o", "s", "D"]
    line_colors = ["#0F4D92", "#767676", "#B64342"]
    for idx, row in enumerate(DATA):
        vals = [row["Precision"], row["Recall"], row["F1"]]
        xpos = x + offsets[idx]
        ax_metrics.vlines(
            xpos,
            0,
            vals,
            color=line_colors[idx],
            alpha=0.35,
            linewidth=1.2,
        )
        ax_metrics.scatter(
            xpos,
            vals,
            s=35,
            marker=marker_styles[idx],
            color=line_colors[idx],
            edgecolor="white",
            linewidth=0.7,
            zorder=3,
            label=row["short"].replace("\n", " "),
        )
        for xi, val in zip(xpos, vals):
            ax_metrics.text(
                xi,
                val + 2.5,
                f"{val:.1f}",
                ha="center",
                va="bottom",
                fontsize=6.4,
                color=line_colors[idx],
            )

    ax_metrics.set_xticks(x)
    ax_metrics.set_xticklabels(metrics)
    ax_metrics.set_ylabel("Metric (%)")
    ax_metrics.set_ylim(0, 82)
    ax_metrics.set_yticks([0, 20, 40, 60, 80])
    ax_metrics.axhline(0, color="#4D4D4D", linewidth=0.8)
    ax_metrics.legend(
        loc="upper right",
        bbox_to_anchor=(1.03, 1.02),
        fontsize=6.2,
        handletextpad=0.5,
        borderaxespad=0,
    )
    ax_metrics.set_title("Precision-recall trade-off", loc="left", fontsize=8, pad=6)
    add_panel_label(ax_metrics, "b")

    fig.text(
        0.075,
        0.055,
        "Evaluation: SCRUBD-CD, function-level source-or-target matching, N=746.",
        fontsize=6.7,
        color="#4D4D4D",
        ha="left",
    )

    base = OUT_DIR / "scrubd_cd_ablation_figure"
    for fmt, kwargs in [
        ("svg", {}),
        ("pdf", {}),
        ("png", {"dpi": 600}),
        ("tiff", {"dpi": 600}),
    ]:
        fig.savefig(base.with_suffix(f".{fmt}"), bbox_inches="tight", **kwargs)
    plt.close(fig)


if __name__ == "__main__":
    main()
