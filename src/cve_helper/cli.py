import argparse
import json
from pathlib import Path

from src.utils.utils import get_logger
from src.cve_helper.cve_helper import (
    build_cve_hints_from_intel_file_with_llm,
    build_cve_hints_from_rules_file,
)

logger = get_logger(__name__)


def main():
    ap = argparse.ArgumentParser("cve_helper")
    ap.add_argument("--out", default="cve_hints.json")

    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--intel", default="", help="single intel bundle file to send into LLM")
    group.add_argument("--cve-rules", default="", help="path to user-provided cve_rules.json")

    # Optional only for multi-entry rules files
    ap.add_argument("--cve-id", default="", help="optional: choose one entry from multi-entry cve_rules.json")

    args = ap.parse_args()

    if args.cve_rules:
        hints = build_cve_hints_from_rules_file(args.cve_rules, cve_id=(args.cve_id or None))
    else:
        # intel -> LLM
        from src.llm.LLM_class import LLM
        llm = LLM()  # keep it minimal; intel file carries meta; LLM can still run without them

        hints = build_cve_hints_from_intel_file_with_llm(llm, args.intel)

    Path(args.out).write_text(json.dumps(hints, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] wrote {args.out}")


if __name__ == "__main__":
    main()