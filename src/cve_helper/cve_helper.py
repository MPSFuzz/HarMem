import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from src.utils.utils import get_logger, extract_json_from_text, clean_markdown_format
from src.cve_helper.schema import normalize_cve_hints, validate_cve_hints

logger = get_logger(__name__)


# ---------- Intel bundle parsing (single file) ----------

_INTEL_HEADER_RE = re.compile(r"^\s*(CVE_ID|LIB_NAME|TARGET_FUNC)\s*:\s*(.+?)\s*$", re.I)
_INTEL_SECTION_RE = re.compile(r"^===\s*(PATCH|ADVISORY|POC|EXTRA)\s*===\s*$", re.M)


def parse_intel_bundle_text(text: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Parse a single intel bundle file.

    Format example:
      CVE_ID: CVE-2025-27113
      LIB_NAME: libxml2
      TARGET_FUNC: xmlPatMatch

      === PATCH ===
      ...
      === ADVISORY ===
      ...
      === POC ===
      ...
      === EXTRA ===
      ...

    Returns:
      meta: {cve_id, lib_name, target_func}
      parts: {patch_text, advisory_text, poc_text, extra_text}
    """
    meta = {"cve_id": "", "lib_name": "", "target_func": ""}
    parts = {"patch_text": "", "advisory_text": "", "poc_text": "", "extra_text": ""}

    if not text or not text.strip():
        return meta, parts

    # parse header (first ~80 lines)
    for line in text.splitlines()[:80]:
        m = _INTEL_HEADER_RE.match(line)
        if not m:
            continue
        key = m.group(1).upper()
        val = m.group(2).strip()
        if key == "CVE_ID":
            meta["cve_id"] = val
        elif key == "LIB_NAME":
            meta["lib_name"] = val
        elif key == "TARGET_FUNC":
            meta["target_func"] = val

    # split sections
    matches = list(_INTEL_SECTION_RE.finditer(text))
    if not matches:
        # no explicit sections -> treat all as extra
        parts["extra_text"] = text.strip()
        return meta, parts

    for i, m in enumerate(matches):
        name = m.group(1).upper()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        chunk = text[start:end].strip()

        if name == "PATCH":
            parts["patch_text"] = chunk
        elif name == "ADVISORY":
            parts["advisory_text"] = chunk
        elif name == "POC":
            parts["poc_text"] = chunk
        elif name == "EXTRA":
            parts["extra_text"] = chunk

    return meta, parts


def parse_intel_bundle_file(path: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return parse_intel_bundle_text(text)


def build_intel_text(parts: Dict[str, str]) -> str:
    """
    Build a single text blob to feed to LLM.
    """
    out = []
    patch = (parts.get("patch_text") or "").strip()
    advisory = (parts.get("advisory_text") or "").strip()
    poc = (parts.get("poc_text") or "").strip()
    extra = (parts.get("extra_text") or "").strip()

    if patch:
        out.append("=== PATCH ===\n" + patch)
    if advisory:
        out.append("=== ADVISORY ===\n" + advisory)
    if poc:
        out.append("=== POC ===\n" + poc)
    if extra:
        out.append("=== EXTRA ===\n" + extra)

    return "\n\n".join(out).strip()


# ---------- Rules file loading ----------

def load_cve_rules_json(path: str) -> Dict[str, Any]:
    """
    Load user-provided cve_rules.json.
    Expected: { "CVE-xxxx-xxxx": { ...rule entry... }, ... }
    """
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(data, dict):
        raise ValueError("cve_rules.json must be a JSON object")
    return data


def select_cve_id_from_rules(rules: Dict[str, Any], cve_id: Optional[str]) -> str:
    """
    If cve_id provided -> use it.
    Else if rules has exactly one key -> use that key.
    Else -> error.
    """
    if cve_id:
        return cve_id

    keys = [k for k in rules.keys() if isinstance(k, str)]
    if len(keys) == 1:
        return keys[0]

    raise ValueError(
        f"rules contains {len(keys)} CVE entries; please specify --cve-id to choose one"
    )


# ---------- Conversion to cve_hints ----------

def cve_rules_entry_to_hints(cve_id: str, rule_entry: Dict[str, Any], source: str) -> Dict[str, Any]:
    """
    Convert one rule entry to normalized cve_hints for framework consumption.
    Keep minimal, avoid lib-specific assumptions.
    """
    hints = {
        "cve_id": cve_id,
        "lib_name": rule_entry.get("lib_name", ""),
        "target_func": rule_entry.get("target_func", ""),
        "bug_class": rule_entry.get("bug_class", "unknown"),
        "touchpoints": rule_entry.get("touchpoints", {}),
        "must_contain": rule_entry.get("must_contain", []),
        "must_avoid": rule_entry.get("must_avoid", []),
        "encourage": rule_entry.get("encourage", []),
        "input_model": rule_entry.get("input_model", {}),
        "repro_oracle": rule_entry.get("repro_oracle", {}),
        "provenance": {
            "sources": [source],
            "confidence": rule_entry.get("confidence", 0.85 if source == "user_rules" else 0.65),
            "notes": rule_entry.get("notes", ""),
        },
    }
    hints = normalize_cve_hints(hints)
    ok, errs = validate_cve_hints(hints)
    if not ok:
        raise ValueError(f"invalid cve_hints: {errs}")
    return hints


# ---------- LLM path: intel -> LLM -> rule entry -> hints ----------

def llm_generate_cve_rules_entry(
    llm,  # src.llm.LLM_class.LLM instance
    cve_id: str,
    lib_name: str,
    target_func: str,
    intel_text: str,
) -> Dict[str, Any]:
    """
    Ask LLM to output ONE cve_rules.json entry: { "CVE-...": {...} }.
    Requires a prompt constant in src/llm/LLM_prompt.py.
    """
    from src.llm.LLM_prompt import CVE_RULES_GENERATE_PROMPT

    prompt = CVE_RULES_GENERATE_PROMPT % (cve_id, cve_id, lib_name, target_func, intel_text)

    # Expect a raw string response. Recommended: add raw_chat() in LLM_class.
    response_text = llm.raw_chat(prompt)

    # Use your existing utilities to extract JSON
    extracted = extract_json_from_text(response_text)
    extracted = clean_markdown_format(extracted)
    obj = json.loads(extracted)

    if not isinstance(obj, dict) or cve_id not in obj or not isinstance(obj[cve_id], dict):
        raise ValueError("LLM output is not a valid single-entry cve_rules.json object")

    return obj  # {cve_id: rule_entry}


def build_cve_hints_from_intel_file_with_llm(llm, intel_file: str) -> Dict[str, Any]:
    meta, parts = parse_intel_bundle_file(intel_file)

    cve_id = (meta.get("cve_id") or "").strip()
    lib_name = (meta.get("lib_name") or "").strip()
    target_func = (meta.get("target_func") or "").strip()

    if not cve_id:
        raise ValueError("intel file missing CVE_ID header (e.g., 'CVE_ID: CVE-2025-27113')")

    intel_text = build_intel_text(parts)
    if not intel_text:
        raise ValueError("intel file has no usable content (PATCH/ADVISORY/POC/EXTRA all empty)")

    obj = llm_generate_cve_rules_entry(llm, cve_id, lib_name, target_func, intel_text)
    return cve_rules_entry_to_hints(cve_id, obj[cve_id], source="llm")


# ---------- Rules path: rules file -> hints ----------

def build_cve_hints_from_rules_file(cve_rules_path: str, cve_id: Optional[str] = None) -> Dict[str, Any]:
    rules = load_cve_rules_json(cve_rules_path)
    chosen = select_cve_id_from_rules(rules, cve_id)

    entry = rules.get(chosen)
    if not isinstance(entry, dict):
        raise ValueError(f"invalid rule entry for {chosen} (expected JSON object)")

    return cve_rules_entry_to_hints(chosen, entry, source="user_rules")