#!/usr/bin/env python3
"""
Side-by-side call-chain figure (replaces the big table).

For one representative bug per library, this plots the sequence of library API
calls each harness performs, official (left) vs. generated (right).

The buggy function is highlighted in red when the generated harness calls it
*directly* (vs. reaching it indirectly through a public API).

Output: callchain_concept.png
"""

import os
import re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BASE = "/root/magma_experiment_recurrence_harness"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "callchain_concept.png")

# ---- representative bug per library -----------------------------------------
# (lib, bug id, buggy function, generated folder, generated harness filename)
REPS = [
    ("lua",       "LUA001", "upvalname",
     "LUA001", "findvararg.c"),
    ("libpng",    "PNG002", "png_image_free_function",
     "PNG002_PNG003_PNG005", "png_check_chunk_length.c"),
    ("libsndfile","SND005", "aiff_read_chanmap",
     "SND005", "aiff_read_chanmap.c"),
    ("libtiff",   "TIF002", "PixarLogDecode",
     "TIF002", "PixarLogDecode.c"),
    ("libxml2",   "XML001", "xmlSnprintfElementContent",
     "XML001_XML017", "xmlSnprintfElementContent__internal_alias.c"),
    ("sqlite3",   "SQL002", "selectExpander",
     "SQL002_SQL003", "selectExpander.c"),
]

OFFICIAL_HARNESS = {
    "lua":       ["official/lua/lua.c"],
    "libpng":    ["official/libpng/libpng_read_fuzzer.cc"],
    "libsndfile":["official/libsndfile/sndfile_fuzzer.cc"],
    "libtiff":   ["official/libtiff/tiff_read_rgba_fuzzer.cc"],
    "libxml2":   ["official/libxml2/libxml2_xml_read_memory_fuzzer.cc"],
    "sqlite3":   ["official/sqlite3/ossfuzz.c"],
}

API_PATTERNS = {
    "libpng":    r"\b(png_[A-Za-z0-9_]+)\s*\(",
    "libsndfile":r"\b(sf_[A-Za-z0-9_]+)\s*\(",
    "libtiff":   r"\b(TIFF[A-Za-z0-9_]+)\s*\(",
    "libxml2":   r"\b((?:xml|html)[A-Z][A-Za-z0-9_]*)\s*\(",
    "lua":       r"\b(lua[A-Za-z0-9_]*)\s*\(",
    "sqlite3":   r"\b(sqlite3_[A-Za-z0-9_]+)\s*\(",
}
DENY = {
    "png_ptr","png_structp","png_infop","png_bytep","png_voidp","png_uint_32",
    "png_alloc_size_t","png_size","png_signature","png_bytes","png_handler",
    "lua_State","lua_Debug","lua_c","lualib","sf_count_t","sqlite3_int64",
    "sqlite3_vfs","sqlite3_stmt","xmlChar","xmlElementPtr","xmlDocPtr",
    "xmlDtdPtr","xmlHashTablePtr","xmlTextReaderPtr","xmlReader",
    "TIFFTAG_IMAGEWIDTH","TIFFTAG_IMAGELENGTH","TIFFTAG_TILEWIDTH",
    "TIFFTAG_BITSPERSAMPLE","TIFFTAG_SAMPLESPERPIXEL","TIFFTAG_PLANARCONFIG",
    "TIFFTAG_ROWSPERSTRIP","TIFFTAG_COMPRESSION",
}


def api_calls(src, lib):
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    pat = API_PATTERNS[lib]
    seen, order = set(), []
    for line in src.splitlines():
        line = line.split("//")[0]
        for m in re.finditer(pat, line):
            n = m.group(1)
            if n in DENY:
                continue
            if n not in seen:
                seen.add(n)
                order.append(n)
    return order


def find_generated(folder, fname):
    d = os.path.join(BASE, folder)
    for root, _, files in os.walk(d):
        for f in files:
            if f.endswith(fname):
                return os.path.join(root, f)
    return None


def draw_chain(ax, x, calls, direct_func=None, color="#444444"):
    """Draw a vertical chain of call boxes at x; top of ax is y=1."""
    n = len(calls)
    step = 0.98 / max(1, n)          # vertical spacing
    box_h = step * 0.55
    for i, c in enumerate(calls):
        y = 0.98 - i * step
        is_direct = (direct_func is not None and c == direct_func)
        fc = "#d62728" if is_direct else color
        ec = "black" if is_direct else "none"
        ax.add_patch(FancyBboxPatch((x, y - box_h / 2), 0.42, box_h,
                                    boxstyle="round,pad=0.004",
                                    fc=fc, ec=ec, lw=0.8))
        ax.text(x + 0.21, y, c, va="center", ha="center",
                fontsize=4.6, color="white" if is_direct else "black")
        if i < n - 1:
            ax.annotate("", xy=(x + 0.21, y - step + box_h / 2),
                        xytext=(x + 0.21, y - box_h / 2),
                        arrowprops=dict(arrowstyle="-", lw=0.5, color="#999999"))


def main():
    fig, axes = plt.subplots(3, 2, figsize=(16, 30))
    axes = axes.flatten()

    for ax, (lib, bug, bfunc, folder, fname) in zip(axes, REPS):
        gen_path = find_generated(folder, fname)
        gen_src = open(gen_path).read() if gen_path else ""
        off_src = ""
        for op in OFFICIAL_HARNESS[lib]:
            fp = os.path.join(BASE, op)
            if os.path.exists(fp):
                off_src += open(fp).read() + "\n"

        gcalls = api_calls(gen_src, lib)
        ocalls = api_calls(off_src, lib)

        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")

        # left = official, right = generated
        draw_chain(ax, 0.02, ocalls, color="#6b8ce6")     # official: blue-ish
        draw_chain(ax, 0.56, gcalls, direct_func=bfunc, color="#8cc08c")  # generated: green

        # column captions
        ax.text(0.23, 1.02, "official", ha="center", va="bottom",
                transform=ax.transAxes, fontsize=9, style="italic",
                color="#4a69bd")
        ax.text(0.77, 1.02, "generated", ha="center", va="bottom",
                transform=ax.transAxes, fontsize=9, style="italic",
                color="#2f7d32")

        direct = bfunc in gcalls
        note = "generated calls buggy fn DIRECTLY" if direct else \
               "buggy fn reached via public API"
        ax.set_title(f"{lib} — {bug}  ({bfunc})\n{note}", fontsize=9.5, pad=8)

    # legend
    from matplotlib.patches import Patch
    legend = [
        Patch(fc="#6b8ce6", label="official harness API calls"),
        Patch(fc="#8cc08c", label="generated harness API calls"),
        Patch(fc="#d62728", label="buggy function (called directly)"),
    ]
    fig.legend(handles=legend, loc="lower center", ncol=3, fontsize=9,
               frameon=False)

    fig.suptitle("Library API call sequences: official vs. generated harness",
                 fontsize=14, y=0.995)
    fig.tight_layout(rect=[0, 0.02, 1, 0.98])
    fig.savefig(OUT, dpi=200, bbox_inches="tight")
    print("saved", OUT)


if __name__ == "__main__":
    main()
