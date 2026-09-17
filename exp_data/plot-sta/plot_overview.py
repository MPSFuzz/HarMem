#!/usr/bin/env python3
"""
Overview concept figure for the harness-comparison paper.

Two panels compare the two harness paradigms:
  (A) Magma official: a few broad, whole-library harnesses, each fanning out to
      many bugs (1 harness -> many bugs).
  (B) Ours (generated): many bug-targeted harnesses, each pointing to one (or a
      small cluster of) bug(s) (1 harness -> 1..few bugs).

Data sources:
  - Official harness/bug mapping is static metadata (from magma configrc + patches).
  - Generated harness/bug mapping is read from 03_barchart.csv (folder -> bug_ids).

Output: overview_concept.png
"""

import csv
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "03_barchart.csv")
OUT = os.path.join(HERE, "overview_concept.png")

# ---- library order + colors -------------------------------------------------
LIBS = ["lua", "libpng", "libsndfile", "libtiff", "libxml2", "sqlite3"]
COLORS = {
    "lua":       "#e6194b",
    "libpng":    "#3cb44b",
    "libsndfile":"#ffe119",
    "libtiff":   "#4363d8",
    "libxml2":   "#f58231",
    "sqlite3":   "#911eb4",
}

# ---- official metadata (static, from magma) ---------------------------------
# harness source files per library (the 7 .c/.cc we shipped)
OFFICIAL_HARNESS = {
    "lua":       ["lua"],
    "libpng":    ["libpng_read_fuzzer"],
    "libsndfile":["sndfile_fuzzer"],
    "libtiff":   ["tiff_read_rgba_fuzzer"],
    "libxml2":   ["libxml2_xml_read_memory_fuzzer",
                  "libxml2_xml_reader_for_file_fuzzer"],
    "sqlite3":   ["ossfuzz"],
}
# number of bugs per library (from magma targets/<lib>/patches/bugs)
OFFICIAL_BUG_COUNT = {
    "lua": 4, "libpng": 7, "libsndfile": 18,
    "libtiff": 14, "libxml2": 17, "sqlite3": 20,
}


def read_generated_mapping():
    """Return list of (folder_name, [bug_ids]) from 03_barchart.csv."""
    mapping = []
    with open(CSV, newline="") as f:
        for row in csv.DictReader(f):
            bugs = [b for b in row["bug_ids"].split(",") if b]
            mapping.append((row["folder"], bugs))
    return mapping


def draw_panel(ax, title, subtitle, harness_groups, bug_groups):
    """
    Draw one bipartite panel.

    harness_groups: list of (label, lib, bug_specs)
        where bug_specs is a list of bug ids (generated, exact) OR
        an int count of anonymous bugs (official, count only).
    bug_groups: dict lib -> list of bug "keys" already laid out by caller.

    We lay out harnesses on x=0 and bugs on x=1, grouped by library.
    """
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # ---- build node positions (deterministic, grouped by lib) ---------------
    # harness nodes
    hy = {}
    y = 0.98
    for lib in LIBS:
        lib_harness = [h for h in harness_groups if h[1] == lib]
        for (label, _, _) in lib_harness:
            hy[label] = y
            y -= 0.045
        y -= 0.05  # gap between libraries

    # bug nodes
    by = {}
    y = 0.98
    for lib in LIBS:
        keys = bug_groups[lib]
        for k in keys:
            by[(lib, k)] = y
            y -= 0.012
        y -= 0.03

    # ---- edges --------------------------------------------------------------
    for (label, lib, bug_specs) in harness_groups:
        if isinstance(bug_specs, int):          # official: count of anonymous bugs
            keys = [f"b{i}" for i in range(bug_specs)]
        else:                                    # generated: exact bug ids
            keys = bug_specs
        x0 = 0.02
        for k in keys:
            y0 = hy[label]
            y1 = by[(lib, k)]
            ax.plot([x0, 0.98], [y0, y1], color=COLORS[lib],
                    lw=0.6, alpha=0.35, zorder=1)

    # ---- harness nodes (rounded boxes) --------------------------------------
    for (label, lib, _) in harness_groups:
        ax.add_patch(FancyBboxPatch((0.0, hy[label] - 0.012), 0.16, 0.024,
                                    boxstyle="round,pad=0.002",
                                    fc=COLORS[lib], ec="none", zorder=3))
        ax.text(0.08, hy[label], label, va="center", ha="center",
                fontsize=5.5, color="black", zorder=4)

    # ---- bug nodes (dots) ---------------------------------------------------
    for (lib, k) in by:
        ax.scatter([0.985], [by[(lib, k)]], s=6, color=COLORS[lib],
                   zorder=2, alpha=0.9)

    ax.set_title(title, fontsize=11, pad=10, loc="center")
    ax.text(0.5, -0.02, subtitle, ha="center", va="top", fontsize=8.5,
            transform=ax.transAxes)

    # column captions
    ax.text(0.08, 1.02, "harnesses", fontsize=9, ha="center", va="bottom",
            transform=ax.transAxes, style="italic")
    ax.text(0.985, 1.02, "bugs", fontsize=9, ha="center", va="bottom",
            transform=ax.transAxes, style="italic")


def main():
    generated = read_generated_mapping()

    # ---- official harness groups (each harness -> anonymous bug count) ------
    official_groups = []
    for lib in LIBS:
        for h in OFFICIAL_HARNESS[lib]:
            official_groups.append((h, lib, OFFICIAL_BUG_COUNT[lib]))

    # ---- generated harness groups (folder -> exact bug ids) -----------------
    generated_groups = []
    for folder, bugs in generated:
        # map each bug to its library via prefix
        prefix = bugs[0][:3].upper()
        lib = {"LUA": "lua", "PNG": "libpng", "SND": "libsndfile",
               "TIF": "libtiff", "XML": "libxml2", "SQL": "sqlite3"}[prefix]
        generated_groups.append((folder, lib, bugs))

    # ---- bug_groups dict: lib -> list of bug keys (union of both panels) ----
    # official: anonymous bug slots; generated: exact ids.  We draw each panel
    # with its own bug_groups, so build them separately.
    official_bugs = {lib: [f"b{i}" for i in range(OFFICIAL_BUG_COUNT[lib])]
                     for lib in LIBS}
    generated_bugs = {}
    for lib in LIBS:
        seen = []
        for (_, l, bugs) in generated_groups:
            if l == lib:
                for b in bugs:
                    if b not in seen:
                        seen.append(b)
        generated_bugs[lib] = seen

    fig, axes = plt.subplots(1, 2, figsize=(14, 7))
    draw_panel(axes[0],
               "(a) Magma official harnesses",
               f"{len(official_groups)} harnesses  ->  {sum(OFFICIAL_BUG_COUNT.values())} bugs "
               f"(avg {sum(OFFICIAL_BUG_COUNT.values())/len(official_groups):.1f} bugs/harness)",
               official_groups, official_bugs)
    draw_panel(axes[1],
               "(b) Our generated harnesses",
               f"{len(generated_groups)} harnesses  ->  {sum(len(v) for v in generated_bugs.values())} bugs "
               f"(avg {sum(len(v) for v in generated_bugs.values())/len(generated_groups):.2f} bugs/harness)",
               generated_groups, generated_bugs)

    # legend
    handles = [plt.Line2D([], [], marker="o", ls="", color=COLORS[l],
                          label=l, markersize=6) for l in LIBS]
    fig.legend(handles=handles, loc="lower center", ncol=len(LIBS),
               fontsize=9, frameon=False)

    fig.suptitle("Harness-to-bug mapping: broad vs. targeted",
                 fontsize=13, y=0.98)
    fig.tight_layout(rect=[0, 0.04, 1, 0.95])
    fig.savefig(OUT, dpi=200, bbox_inches="tight")
    print("saved", OUT)


if __name__ == "__main__":
    main()
