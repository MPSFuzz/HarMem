#!/usr/bin/env python3
"""
Grouped bar chart (replaces the numeric table).

Compares the generated harnesses vs. the Magma official harness across the
6 libraries on two metrics:
  (a) lines of code (LOC)
  (b) number of distinct library API calls

For each library the official value is a single harness (constant), while the
generated side shows the mean across the per-bug harness folders, with
min--max range bars.

Data: 03_barchart.csv (same directory).

Output: barchart_concept.png
"""

import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "03_barchart.csv")
OUT = os.path.join(HERE, "barchart_concept.png")

LIBS = ["lua", "libpng", "libsndfile", "libtiff", "libxml2", "sqlite3"]


def load():
    data = defaultdict(lambda: {"loc": [], "api": []})
    official = {}
    with open(CSV, newline="") as f:
        for row in csv.DictReader(f):
            lib = row["lib"]
            data[lib]["loc"].append(int(row["generated_loc"]))
            data[lib]["api"].append(int(row["generated_distinct_api_calls"]))
            official[lib] = (int(row["official_loc"]),
                             int(row["official_distinct_api_calls"]))
    return data, official


def main():
    data, official = load()

    metrics = [
        ("loc", "Lines of code (LOC)"),
        ("api", "Distinct library API calls"),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    x = np.arange(len(LIBS))
    width = 0.36

    for ax, (metric, title) in zip(axes, metrics):
        off_vals = np.array([official[lib][0 if metric == "loc" else 1]
                             for lib in LIBS], dtype=float)
        gen_mean = np.array([np.mean(data[lib][metric]) for lib in LIBS])
        gen_min = np.array([np.min(data[lib][metric]) for lib in LIBS])
        gen_max = np.array([np.max(data[lib][metric]) for lib in LIBS])
        gen_err = [gen_mean - gen_min, gen_max - gen_mean]   # asymmetric range

        ax.bar(x - width / 2, off_vals, width, label="Magma official",
               color="#6b8ce6", edgecolor="black", lw=0.5)
        ax.bar(x + width / 2, gen_mean, width, label="Ours (generated, mean)",
               color="#8cc08c", edgecolor="black", lw=0.5,
               yerr=gen_err, capsize=3, error_kw=dict(lw=0.8, ecolor="#333333"))

        ax.set_xticks(x)
        ax.set_xticklabels(LIBS, fontsize=9)
        ax.set_ylabel(title, fontsize=10)
        ax.set_ylim(0, ax.get_ylim()[1] * 1.15)
        ax.grid(axis="y", ls="--", alpha=0.4)
        ax.set_axisbelow(True)
        ax.tick_params(axis="y", labelsize=8)

    axes[0].legend(fontsize=9, frameon=False, loc="upper right")
    fig.suptitle("Harness complexity: Magma official vs. generated",
                 fontsize=13, y=0.99)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(OUT, dpi=200, bbox_inches="tight")
    print("saved", OUT)


if __name__ == "__main__":
    main()
