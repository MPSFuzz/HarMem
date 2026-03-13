import json
from typing import Any, Dict, List, Tuple

CVEHints = Dict[str, Any]


def _as_list(x) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def normalize_cve_hints(h: Dict[str, Any]) -> CVEHints:
    """
    Normalize to a stable schema for downstream framework components.
    Keep it minimal and general (works across libraries).
    """
    out: CVEHints = dict(h or {})
    out.setdefault("cve_id", "")
    out.setdefault("lib_name", "")
    out.setdefault("target_func", "")
    out.setdefault("bug_class", "unknown")

    out["must_contain"] = [str(v) for v in _as_list(out.get("must_contain")) if str(v).strip()]
    out["must_avoid"] = [str(v) for v in _as_list(out.get("must_avoid")) if str(v).strip()]
    out["encourage"] = [str(v) for v in _as_list(out.get("encourage")) if str(v).strip()]

    out.setdefault("input_model", {})
    im = dict(out["input_model"] or {})
    im.setdefault("layout", "unknown")
    im.setdefault("pattern_kind", "unknown")  # text/bytes/unknown

    # accept both "templates" and legacy "pattern_templates"
    templates = im.get("templates", im.get("pattern_templates", []))
    im["templates"] = [str(v) for v in _as_list(templates) if str(v).strip()]

    im["mutation_knobs"] = [str(v) for v in _as_list(im.get("mutation_knobs")) if str(v).strip()]
    out["input_model"] = im

    out.setdefault("repro_oracle", {})
    ro = dict(out["repro_oracle"] or {})
    ro.setdefault("signal", ["crash"])
    ro["signal"] = [str(v) for v in _as_list(ro.get("signal")) if str(v).strip()]
    ro.setdefault("differential", False)
    out["repro_oracle"] = ro

    out.setdefault("touchpoints", {})
    tp = dict(out["touchpoints"] or {})
    tp.setdefault("files", [])
    tp.setdefault("functions", [])
    tp.setdefault("tokens", [])
    tp["files"] = [str(v) for v in _as_list(tp.get("files")) if str(v).strip()]
    tp["functions"] = [str(v) for v in _as_list(tp.get("functions")) if str(v).strip()]
    tp["tokens"] = [str(v) for v in _as_list(tp.get("tokens")) if str(v).strip()]
    out["touchpoints"] = tp

    out.setdefault("provenance", {})
    pv = dict(out["provenance"] or {})
    pv.setdefault("sources", [])
    pv["sources"] = [str(v) for v in _as_list(pv.get("sources")) if str(v).strip()]
    pv.setdefault("confidence", 0.5)
    try:
        pv["confidence"] = float(pv["confidence"])
    except Exception:
        pv["confidence"] = 0.5
    pv.setdefault("notes", "")
    out["provenance"] = pv

    return out


def validate_cve_hints(h: CVEHints) -> Tuple[bool, List[str]]:
    errs = []
    if not h.get("cve_id"):
        errs.append("missing cve_id")
    if "input_model" not in h:
        errs.append("missing input_model")
    if "repro_oracle" not in h:
        errs.append("missing repro_oracle")
    return (len(errs) == 0, errs)