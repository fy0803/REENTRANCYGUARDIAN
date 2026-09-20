from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"
plt.rcParams["pdf.fonttype"] = 42


OUT_DIR = Path("figures/function_level_comparison")
OUT_DIR.mkdir(parents=True, exist_ok=True)

columns = ["Tool", "Our Method", "Slither", "Mythril", "Sailfish", "SliSE"]
rows = [
    ["Dataset", "Function-level\n(746)", "Function-level\n(746)", "Function-level\n(746)", "Function-level\n(746)", "Function-level\n(746)"],
    ["# TP", "157", "225", "66", "18", "34"],
    ["# FP", "94", "328", "75", "8", "70"],
    ["# FN", "70", "2", "99", "134", "193"],
    ["# TN", "425", "191", "315", "350", "449"],
    ["P", "0.625", "0.407", "0.468", "0.692", "0.327"],
    ["R", "0.692", "0.991", "0.400", "0.118", "0.150"],
    ["F", "0.657", "0.577", "0.431", "0.202", "0.205"],
]


def main() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 4.65))
    ax.axis("off")

    table = ax.table(
        cellText=rows,
        colLabels=columns,
        cellLoc="center",
        colLoc="center",
        loc="center",
        colWidths=[0.14, 0.20, 0.16, 0.16, 0.16, 0.16],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)

    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor("#222222")
        cell.set_linewidth(0.8)
        cell.set_facecolor("white")
        cell.set_height(0.105)
        cell.PAD = 0.03

        text = cell.get_text()
        if r == 0:
            text.set_fontweight("bold")
            text.set_fontsize(10.5)
            cell.set_linewidth(1.0)
        if c == 0:
            text.set_fontweight("bold")
            text.set_fontsize(10.5)
        if c == 1 and r > 0:
            text.set_fontweight("semibold")

    # Slightly taller dataset row for two-line entries.
    for c in range(len(columns)):
        table[(1, c)].set_height(0.118)

    fig.subplots_adjust(left=0.02, right=0.98, top=0.96, bottom=0.04)

    base = OUT_DIR / "function_level_comparison_table"
    fig.savefig(base.with_suffix(".svg"), bbox_inches="tight")
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight")
    fig.savefig(base.with_suffix(".tiff"), dpi=600, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
