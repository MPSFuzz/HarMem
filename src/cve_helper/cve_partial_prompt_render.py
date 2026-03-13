import json
from typing import Any, Dict, List

def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def extract_structural_cve_model(cve_hints: Dict[str, Any]) -> Dict[str, Any]:
    h = cve_hints or {}
    if not isinstance(h, dict) or not h:
        return {
            "is_cve_guided": False,
            "multi_input_roles": False,
            "input_roles": [],
            "must_have_constructs": [],
            "avoid_patterns": [],
            "bug_touchpoints": [],
            "preferred_layout": "unknown",
            "pattern_kind": "unknown",
        }

    input_model = h.get("input_model", {}) or {}
    must_contain = _as_list(h.get("must_contain"))
    must_avoid = _as_list(h.get("must_avoid"))
    touchpoints = h.get("touchpoints", {}) or {}

    input_roles: List[str] = []
    text_blob = " ".join(
        [str(x) for x in must_contain]
        + [str(x) for x in input_model.get("critical_fields", [])]
        + [str(x) for x in input_model.get("templates", [])]
    ).lower()

    if "schema" in text_blob:
        input_roles.append("schema")
    if "instance" in text_blob or "document" in text_blob or "xml document" in text_blob:
        input_roles.append("instance")

    input_roles = list(dict.fromkeys(input_roles))

    return {
        "is_cve_guided": True,
        "multi_input_roles": len(input_roles) > 1,
        "input_roles": input_roles,
        "must_have_constructs": [str(x) for x in must_contain if str(x).strip()],
        "avoid_patterns": [str(x) for x in must_avoid if str(x).strip()],
        "bug_touchpoints": [str(x) for x in _as_list(touchpoints.get("functions")) if str(x).strip()],
        "preferred_layout": input_model.get("layout", "unknown"),
        "pattern_kind": input_model.get("pattern_kind", "unknown"),
    }

def render_cve_hints_for_skeleton(cve_hints: Dict[str, Any]) -> str:
    model = extract_structural_cve_model(cve_hints)
    if not model.get("is_cve_guided"):
        return ""

    lines = []
    lines.append("=== CVE-AWARE STRUCTURAL CONSTRAINTS ===")
    lines.append("This harness is intended for vulnerability reproduction, not only generic API coverage.")
    lines.append(f"- multi_input_roles: {model.get('multi_input_roles')}")
    roles = model.get("input_roles", [])
    if roles:
        lines.append(f"- semantic input roles: {', '.join(roles)}")
    lines.append(f"- preferred_layout: {model.get('preferred_layout')}")
    lines.append(f"- pattern_kind: {model.get('pattern_kind')}")

    musts = model.get("must_have_constructs", [])
    avoids = model.get("avoid_patterns", [])
    tps = model.get("bug_touchpoints", [])

    if tps:
        lines.append("- bug-relevant touchpoints:")
        for x in tps[:12]:
            lines.append(f"  * {x}")

    if musts:
        lines.append("- MUST preserve at skeleton level:")
        for x in musts[:12]:
            lines.append(f"  * {x}")

    if avoids:
        lines.append("- MUST avoid at skeleton level:")
        for x in avoids[:12]:
            lines.append(f"  * {x}")

    lines.append(
        "- If the vulnerability depends on multiple semantic roles (for example schema + instance), "
        "the skeleton MUST reserve explicit code structure for those roles instead of collapsing them "
        "into one generic input object."
    )

    return "\n".join(lines)

def render_cve_hints_for_codegen(cve_hints: Dict[str, Any], target_api: str = "") -> str:
    h = cve_hints or {}
    if not isinstance(h, dict) or not h:
        return ""

    cve_id = h.get("cve_id", "")
    bug_class = h.get("bug_class", "")
    tp = h.get("touchpoints", {}) or {}
    im = h.get("input_model", {}) or {}
    ro = h.get("repro_oracle", {}) or {}

    lines = []
    lines.append("=== CVE-SPECIFIC BUG REPRODUCTION CONSTRAINTS ===")
    if cve_id:
        lines.append(f"- CVE: {cve_id}")
    if bug_class:
        lines.append(f"- bug_class: {bug_class}")
    if target_api:
        lines.append(f"- harness-driving target API: {target_api}")

    funcs = _as_list(tp.get("functions"))
    tokens = _as_list(tp.get("tokens"))
    files = _as_list(tp.get("files"))

    if funcs:
        lines.append("- bug-relevant internal touchpoints:")
        for x in funcs[:15]:
            lines.append(f"  * {x}")
    if files:
        lines.append("- relevant files:")
        for x in files[:10]:
            lines.append(f"  * {x}")
    if tokens:
        lines.append("- key bug tokens / concepts:")
        for x in tokens[:20]:
            lines.append(f"  * {x}")

    musts = _as_list(h.get("must_contain"))
    avoids = _as_list(h.get("must_avoid"))
    encourages = _as_list(h.get("encourage"))

    if musts:
        lines.append("- HARD MUST constraints:")
        for x in musts[:15]:
            lines.append(f"  * {x}")
    if avoids:
        lines.append("- HARD MUST AVOID constraints:")
        for x in avoids[:15]:
            lines.append(f"  * {x}")
    if encourages:
        lines.append("- Soft encouragement:")
        for x in encourages[:12]:
            lines.append(f"  * {x}")

    lines.append("- input_model:")
    lines.append(json.dumps(im, indent=2, ensure_ascii=False))

    lines.append("- repro_oracle:")
    lines.append(json.dumps(ro, indent=2, ensure_ascii=False))

    lines.append(
        "Interpretation rule: The target function in the harness call chain may differ from the deeper bug point. "
        "Design the harness so that calling the target API has a realistic chance to reach the bug-relevant internal touchpoints."
    )

    return "\n".join(lines)

def render_cve_hints_for_upgrade(cve_hints: Dict[str, Any]) -> str:
    h = cve_hints or {}
    if not isinstance(h, dict) or not h:
        return ""

    lines = []
    lines.append("=== CVE-SPECIFIC PRIORS / CONSTRAINTS ===")
    lines.append("The current harness should preserve CVE-aware input structure unless runtime evidence clearly shows that structure is wrong.")
    lines.append(render_cve_hints_for_codegen(h))
    lines.append(
        "Upgrade guidance: Prefer localized repairs. Do not collapse multiple semantic input roles into a single generic input unless trace evidence strongly suggests the current role separation is invalid."
    )
    return "\n".join(lines)

def render_cve_hints_for_seed_generation(cve_hints: Dict[str, Any]) -> str:
    h = cve_hints or {}
    if not isinstance(h, dict) or not h:
        return ""

    im = h.get("input_model", {}) or {}
    musts = _as_list(h.get("must_contain"))
    templates = _as_list(im.get("templates"))
    knobs = _as_list(im.get("mutation_knobs"))

    lines = []
    lines.append("=== CVE-SPECIFIC SEED CONSTRAINTS ===")
    lines.append(f"- CVE: {h.get('cve_id', '')}, bug_class={h.get('bug_class', '')}")
    lines.append(f"- expected layout: {im.get('layout', 'unknown')}")
    lines.append(f"- pattern_kind: {im.get('pattern_kind', 'unknown')}")

    if musts:
        lines.append("- MUST reflect in generated seeds:")
        for x in musts[:12]:
            lines.append(f"  * {x}")

    if templates:
        lines.append("- Preferred templates:")
        for x in templates[:12]:
            lines.append(f"  * {x}")

    if knobs:
        lines.append("- Mutation knobs to vary:")
        for x in knobs[:12]:
            lines.append(f"  * {x}")
            
    return "\n".join(lines)