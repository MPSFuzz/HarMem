import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from clang import cindex

from src.utils.utils import get_logger
from src.utils.libclang_load import load_libclang
from src.utils.static_analyze_clang_args import enrich_clang_args_for_analysis

from src.static_analyze.ccdb import CCDB
from src.static_analyze.extractor.signature_extractor import SignatureExtractor
from src.static_analyze.extractor.bitmask_extractor import BitmaskExtractor
from src.static_analyze.extractor.guard_extractor import GuardExtractor, build_bitmask_index
from src.static_analyze.extractor.resource_extractor import ResourceExtractor
from src.static_analyze.extractor.sourcecode_extractor import ImplementationExtractor

#load_libclang()
logger = get_logger(__name__)

FLAGY = re.compile(r'(?:flags?|options?|mode|access|mask|perm|type)$', re.I)        # if these appear in a param name, it's likely a bitmask

# some dataclass to-dict support functions
def _asdict_guard(g) -> Dict:
    # g is the GuardCond instance
    return {
        "kind": getattr(g, "kind", None),
        "expr": getattr(g, "expr", None),
        "location": getattr(g, "location", None),
        "func_context": getattr(g, "func_context", None),
        "file": getattr(g, "file", None),
        "tags": list(getattr(g, "tags", []) or []),
        "ids": list(getattr(g, "ids", []) or []),
        "bitmask_hint": list(getattr(g, "bitmask_hint", []) or [])
    }

def _asdict_res(o) -> Dict:
    # o is the ResourceOp instance
    return {
        "kind": getattr(o, "kind", None),
        "func": getattr(o, "func", None),
        "location": getattr(o, "location", None),
        "func_context": getattr(o, "func_context", None),
        "file": getattr(o, "file", None),
        "tags": list(getattr(o, "tags", []) or []),
        "related": getattr(o, "related", None),
        "ids": list(getattr(o, "ids", []) or [])
    }

# call back functions process
_COMMON_NON_VENDOR_PREFIXES = {
    'get','set','new','free','init','deinit','cleanup','create','destroy',
    'open','close','start','stop','read','write','alloc','realloc','dup',
    'load','save','parse','print','dump','walk','test','process','handle'
}

def _leading_token(name: str) -> Optional[str]:
    if not name:
        return None
    if '_' in name:
        return name.split('_', 1)[0].lower()
    m = re.match(r'^([a-z]+|[A-Z]+)(?=[A-Z]|_|$)', name)
    return m.group(1).lower() if m else None

def _strip_vendor_prefix(s: str, vendor_prefixes: List[str]) -> str:
    s = s or ''
    low = s.lower()
    for p in vendor_prefixes or []:
        p_low = p.lower()
        if low.startswith(p_low + '_'):
            return s[len(p_low)+1:]
        if low.startswith(p_low) and len(s) > len(p_low):
            nxt = s[len(p_low):len(p_low)+1]
            if nxt and not nxt.islower():
                return s[len(p_low):]
    return s

def _base_typename(t: str) -> str:
    t = (t or '').replace('const', '').replace('volatile', '').replace('*', ' ')
    toks = [x for x in t.strip().split() if x]
    return toks[-1] if toks else t.strip()

def _looks_like_cb_typedef(t: str) -> bool:
    if not t:
        return False
    squashed = ''.join((t or '').split())
    if '(*' in squashed and ')' in squashed:
        return True
    alias = _base_typename(t).lower()
    return alias.endswith(('callback','handler','loader','func','hook'))

def _is_callback_edge(caller_sig: Dict, callee_sig: Dict, vendor_prefixes: List[str]) -> Optional[str]:
    callee_name = callee_sig.get("name") or ""
    ccore = _strip_vendor_prefix(callee_name, vendor_prefixes).lower()
    for p in (caller_sig.get("parameters") or []):
        t = p.get("type") or ""
        if not _looks_like_cb_typedef(t):
            continue
        alias = _base_typename(t)
        acore = _strip_vendor_prefix(alias, vendor_prefixes).lower()
        if acore and (acore in ccore or ccore in acore):
            return p.get("name") or alias
    return None

def _merge_unique(a: List[Dict], b: List[Dict]) -> List[Dict]:
    seen, out = set(), []
    for g in (a or []) + (b or []):
        key = (g.get('expr'), g.get('location'))
        if key not in seen:
            seen.add(key)
            out.append(g)
    return out

class Aggregator:
    def __init__(self,
                 ccdb_path: str,
                 include_headers: Optional[bool] = False,
                 system_includes: Optional[bool] = False,
                 bitmask_require_op: Optional[bool] = True,
                 max_guards_per_node: int = 4,
                 vendor_prefixes: Optional[List[str]] = None,      # explicit vendor prefixes
                 infer_vendor_prefixes: bool = True,               # auto infer vendor prefixes from the function names in the CCDB
                 vendor_prefix_threshold: float = 0.25,            # the frequency threshold to consider a leading token as vendor prefix
                 min_vendor_len: int = 2 
                 ) -> None:
        self.ccdb = CCDB.from_path(ccdb_path)
        self.idx = cindex.Index.create()
        
        self.include_headers = include_headers
        self.system_includes = system_includes
        self.bitmask_require_op = bitmask_require_op
        self.max_guards_per_node = max_guards_per_node

        # information from extractors
        self.sigs: List[Dict] = []
        self.bitmask_groups: List[Dict] = []
        self.guards: List[Dict] = []
        self.resources: List[Dict] = []

        # fast indexes 
        self.sig_by_name: Dict[str, List[Dict]] = {}
        self.sig_by_usr: Dict[str, Dict] = {}
        self.bm_index: Dict[str, Dict] = {}
        self.guard_by_func: Dict[str, List[Dict]] = {}
        self.res_by_func: Dict[str, List[Dict]] = {}

        # prefixes infer
        self._user_vendor_prefixes = set((vendor_prefixes or []))
        self._infer_vendor_prefixes = bool(infer_vendor_prefixes)
        self._vendor_prefix_threshold = float(vendor_prefix_threshold)
        self._min_vendor_len = int(min_vendor_len)
        self._vendor_prefixes: List[str] = []

    def _split_compile_runtime_guards(self, guards: List[Dict]) -> Tuple[List[Dict], List[str]]:
        runtime, macros = [], []
        for g in guards or []:
            expr = (g.get("expr") or "")
            tags = " ".join(g.get("tags") or [])
            is_compile = (
                "#if" in expr or "ifdef" in expr or "ifndef" in expr or "defined(" in expr or
                " pp-" in f" {tags}"
            )
            if is_compile:
                macs = re.findall(r'\b(?:defined\s*\()?\s*([A-Za-z_][A-Za-z0-9_]*)', expr)
                for m in macs:
                    if m not in {"NULL", "if", "else", "endif", "defined"}:
                        macros.append(m)
            else:
                runtime.append(g)
        return runtime, sorted(set(macros))
    
    def _normalize_required_from_intrinsic(self, guards: List[Dict], callee_sig: Dict) -> List[Dict]:
        out = []
        for g in guards or []:
            expr = g.get("expr") or ""
            if "null-check" in (g.get("tags") or []):
                m1 = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*==\s*NULL\b', expr)
                if m1:
                    out.append({
                        "kind": "required",
                        "expr": f"{m1.group(1)} != NULL",
                        "location": g.get("location"),
                        "file": g.get("file")
                    })
        # 去重
        seen = set()
        uniq = []
        for r in out:
            k = (r["kind"], r["expr"])
            if k not in seen:
                seen.add(k)
                uniq.append(r)
        return uniq
    
    def _annotate_resources_ownership(self, node: Dict, sig: Dict) -> None:
        params = {p.get("name", ""): (p.get("type") or "") for p in (sig.get("parameters") or [])}
        out_names = {n for n, t in params.items() if re.search(r'\*\s*\*', t or "")}

        for r in node.get("resources") or []:
            if r.get("kind") == "alloc" and out_names and (set(r.get("ids") or []) & out_names):
                r["ownership"] = "transferred_via_outparam"
                r["freed_by"] = "caller"

        frees_by_id: Dict[str, List[Dict]] = {}
        for r in node.get("resources") or []:
            if r.get("kind") == "free":
                for rid in (r.get("ids") or []):
                    frees_by_id.setdefault(rid, []).append(r)
        for rid, frees in frees_by_id.items():
            if len(frees) > 1:
                for fr in frees[:-1]:
                    fr["free_on_error"] = True

    def _pick_sig_by_name(self, name: str) -> Dict:
        cands = self.sig_by_name.get(name, [])
        if not cands:
            return {"usr": f"__unknown__:{name}", "name": name, "parameters": [], "return_type": "", "file": None, "location": None}
        
        return max(cands, key=lambda s: len(s.get("parameters", [])) or 0)
    
    def _cannon_sig(self, s: Dict) -> Dict:
        return{
            "return": s.get("return_type", ""),
            "params": [{"name": p.get("name", ""), "type": p.get("type", "")} for p in (s.get("parameters") or [])]
        }
    
    def _node_lifcycle_steps(self, func_name: str) -> List[Dict]:
        ops = self.res_by_func.get(func_name, [])
        steps = []
        for op in ops:
            if op.get("kind") in ("alloc", "free", "transfer"):
                steps.append({
                    "step": op["kind"],
                    "func": op.get("func"),
                    "location": op.get("location"),
                    "ids": op.get("ids") or []
                })
        
        return steps
    
    def _bindings_placeholder(self, callee_sig: Dict) -> List[Dict]:
        out = []
        for i, p in enumerate(callee_sig.get("parameters") or []):
            pname = p.get("name") or f"param{i}"
            out.append({"param": pname, "type": p.get("type", ""), "arg": f"$ARG_{pname}"})
        
        return out
    
    def _collect_externals(self) -> List[str]:  # New method to collect externals
        externals = set()
        for sig in self.sigs:
            if 'external' in sig.get('tags', []):
                externals.add(sig.get('name'))
        return list(externals)
    
    def _select_guards(self, guards: List[Dict], bindings: List[Dict], max_keep: int = 4) -> List[Dict]:
        if not guards:
            return []
        pnames = {b['param'] for b in bindings}
        socred = []
        for g in guards:
            tags = g.get("tags") or []
            ids = set(g.get("ids") or [])
            s = 0 
            if ids & pnames:
                s += 2
            if 'flag-check' in tags:
                s += 3
            if 'null-check' in tags:
                s += 2
            if 'length-check' in tags:
                s += 1
            if g.get('bitmask_hint'):
                s += 3
            if s > 0:
                socred.append((s, g))

        socred.sort(key=lambda x: x[0], reverse=True)
        
        return [g for _, g in socred[:max_keep]]
    
    def _infer_visibility(self, sig: Dict) -> str:
        vis = sig.get("visibility")
        if vis in ("external", "internal"):
            return vis

        tags = sig.get("tags") or []
        tags_l = {t.lower() for t in tags}

        if "static" in tags_l or "internal" in tags_l:
            return "internal"

        return "external"

    def _edge_flags_from_guards_or_typename(self, guards: List[Dict], bindings: List[Dict], bitmask_groups: List[Dict]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        flag_params = [b for b in bindings if FLAGY.search(b['param'])]
        if not flag_params:
            return out
        
        #1 try to use bitmask_hint from guards
        hits = []
        for g in guards:
            for h in (g.get('bitmask_hint') or []):
                if h and h.get('name') and h.get("group"):
                    hits.append(h)
        if hits:
            by_group: Dict[str, List[Dict]] = {}
            for h in hits:
                by_group.setdefault(h['group'], []).append(h)
            for b in flag_params:
                gkey, ghits = next(iter(by_group.items()))
                names = [x['name'] for x in ghits]
                out[b['param']] = {
                    "bundle_key": gkey,
                    "candidates": names,
                    "suggested_value": " | ".join(sorted(set(names))) if names else '0',
                    "bit_width": ghits[0].get("bit_width")
                }
            
            return out
        
        #2 try to guess bitmask_groups by param type name
        def guess_group_by_type(t: str) -> Optional[str]:
            t_up = (t or "").upper()
            if not t_up:
                return None
            for g in bitmask_groups:
                k = (g.get("key") or "").upper()
                if not k:
                    continue
                if k in t_up or t_up in k:
                    return g.get('key')
                k0 = k.split('_')[0]
                if k0 and k0 in t_up:
                    return g.get('key')
            
            return None
        
        bm_index = {
            g.get("key"):{
                'names':[
                    v.get('name')
                    for v in (g.get('value') or [])
                    if isinstance(v, dict) and v.get('name')
                ],
                "bit_width": g.get("bit_width_hint")
            }
            for g in bitmask_groups
        }

        for b in flag_params:
            gkey = guess_group_by_type(b.get("type", ""))
            if gkey and gkey in bm_index:
                names = bm_index[gkey]['names'][:2]
                out[b["param"]] = {
                    'bundle_key': gkey,
                    'candidates': names,
                    'suggested_value': ' | '.join(names) if names else '0',
                    'bit_width': bm_index[gkey]['bit_width'],
                }
            else:
                out[b['param']] = {
                    'bundle_key': None,
                    'candidates': [],
                    'suggested_value': '0',
                    'bit_width': None,
                }

        return out
    
    def _collect_param_defaults(self, edges_outs: List[Dict]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for e in edges_outs:
             for param, meta in (e.get("arg_flags") or {}).items():
                 sv = meta.get("suggested_value")
                 if sv is not None:
                     key = f"{e['from_usr']}->{e['to_usr']}:{param}"
                     out[key] = sv
        
        return out

    def scan_project_for_call_chain(self, name_chain:List[str]) -> None:
        # scan all TUs in the CCDB by the given name_chain, and run all extractors on matched functions
        name_set = set(name_chain)

        relevent_tus: List[Tuple[Any, List[Dict]]] = []

        leading_token_count: Dict[str, int] = {}
        total_names = 0

        for tu_meta in self.ccdb.iter_tus():
            args = self.ccdb.clang_args_for(tu_meta)
            args = enrich_clang_args_for_analysis(args, compiler=tu_meta.compiler)

            sig_extractor = SignatureExtractor(clang_args=args, include_headers=self.include_headers, system_includes=self.system_includes)
            sigs = sig_extractor.extract_from_file(tu_meta.file)
            for s in sigs:
                self.sigs.append(s)
                self.sig_by_usr[s['usr']] = s
                self.sig_by_name.setdefault(s['name'], []).append(s)

                tok = _leading_token(s.get('name', ''))
                if tok and tok not in _COMMON_NON_VENDOR_PREFIXES:
                    leading_token_count[tok] = leading_token_count.get(tok, 0) + 1
                    total_names += 1

            if any(s['name'] in name_set for s in sigs):
                relevent_tus.append((tu_meta, sigs))
        
        inferred: List[str] = []
        if self._infer_vendor_prefixes and total_names > 0:
            for tok, cnt in leading_token_count.items():
                if len(tok) >= self._min_vendor_len and cnt / total_names >= self._vendor_prefix_threshold:
                    inferred.append(tok)
        merged = {p.lower() for p in self._user_vendor_prefixes} | set(inferred)
        self._vendor_prefixes = sorted(merged)
        
        # get bitmask / guards / resources from relevent TUs
        bm_ex = BitmaskExtractor(require_bit_operator=self.bitmask_require_op, min_group_size=2)
        res_ex = ResourceExtractor()

        bm_groups_all: List[Dict] = []
        tus_cache: List[Tuple[Any, Any]] = []
        for tu_meta, _ in relevent_tus:
            args = self.ccdb.clang_args_for(tu_meta)
            tu = self.idx.parse(tu_meta.file, args=args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            macros = self.ccdb.macros_dump(tu_meta.language)
            groups = bm_ex.extract_from_tu(tu, macros=macros)
            groups_dict = bm_ex.groups_to_dict(groups)
            bm_groups_all.extend(groups_dict)
            tus_cache.append((tu_meta, tu))
        
        self.bitmask_groups = bm_groups_all
        self.bm_index = build_bitmask_index(groups=bm_groups_all)

        for tu_meta, tu in tus_cache:
            guard_ex = GuardExtractor(known_bitmask_index=self.bm_index, known_bitmask_names=set(self.bm_index.keys()))
            guards = guard_ex.extract_from_tu(tu=tu)
            self.guards.extend([_asdict_guard(g) for g in guards])

            res = res_ex.extract_from_tu(tu=tu)
            self.resources.extend([_asdict_res(o) for o in res])

        # get guards / resource fast indexes (by function name)
        for g in self.guards:
            k = g.get("func_context") or g.get("func")
            if k:
                self.guard_by_func.setdefault(k, []).append(g)
        
        for r in self.resources:
            k = r.get("func_context") or r.get("func")
            if k:
                self.res_by_func.setdefault(k, []).append(r)
        
    def build_plan_for_chain(self, name_chain: List[str]) -> Dict:
        # 1) 准备签名与 USR
        sigs_seq = [self._pick_sig_by_name(nm) for nm in name_chain]
        usrs = [s.get('usr') or f"__unknown__:{s.get('name')}" for s in sigs_seq]

        nodes_out, edges_out = [], []
        lifcycle: List[Dict] = []
        bitmask_seen_keys = set()

        # 2)仅放 callee 固有前置条件 placeholder，资源稍后再补 ownership
        for i, sig in enumerate(sigs_seq):
            fname = sig.get("name")
            node = {
                "usr": usrs[i],
                "name": fname,
                "signature": self._cannon_sig(sig),
                "file": sig.get("file"),
                "location": sig.get("location"),
                "preconditions": [],
                "resources": (self.res_by_func.get(fname, [])[:6]),
                "visibility": self._infer_visibility(sig)
            }
            lifcycle.extend(self._node_lifcycle_steps(fname))
            nodes_out.append(node)

        # 3) 建边：处理回调注册、拆分 callsite 守卫、补 bitmask 建议
        for i in range(len(sigs_seq)-1):
            caller, callee = sigs_seq[i], sigs_seq[i+1]
            caller_name, callee_name = caller.get("name"), callee.get("name")

            bindings = self._bindings_placeholder(callee)

            cb_param = _is_callback_edge(caller, callee, self._vendor_prefixes)
            call_kind = "direct"
            callback_param_for_edge = cb_param

            if cb_param:
                call_kind = "callback_registration"
                callback_target = None
                if i + 2 < len(sigs_seq):
                    callback_target = sigs_seq[i + 2].get("name")
                for b in bindings:
                    if b["param"] == cb_param:
                        b["arg"] = callback_target or b["arg"]
                        break

            if edges_out:
                prev = edges_out[-1]
                if prev.get("call_kind") == "callback_registration":
                    prev_bindings = prev.get("param_bindings", [])
                    prev_cb_param = prev.get("callback_param")

                    prev_target = None
                    if prev_cb_param:
                        pb = next((x for x in prev_bindings if x.get("param") == prev_cb_param), None)
                        if pb:
                            prev_target = pb.get("arg")

                    # 2) 兜底：即使没有 callback_param，也在所有绑定里查有没有把回调名当作 arg
                    if prev_target is None:
                        hit = next((x for x in prev_bindings if x.get("arg") == callee_name), None)
                        if hit:
                            prev_target = hit.get("arg")

                    if prev_target == callee_name:
                        call_kind = "callback_invoke"
                        callback_param_for_edge = None

            else:
                call_kind = "direct"

            callee_guards_all = [g for g in (self.guard_by_func.get(callee_name, []) or [])
                                 if (g.get("func_context") == callee_name or g.get("func") == callee_name)]
            callee_intrinsic = self._select_guards(callee_guards_all, bindings, self.max_guards_per_node)
            nodes_out[i + 1]['preconditions'] = self._normalize_required_from_intrinsic(callee_intrinsic, callee)

            caller_guards_all = [g for g in (self.guard_by_func.get(caller_name, []) or [])
                                 if (g.get("func_context") == caller_name or g.get("func") == caller_name)]
            callsite_runtime_all = self._select_guards(caller_guards_all, bindings, max(1, self.max_guards_per_node // 2))
            callsite_runtime, compile_time_macros = self._split_compile_runtime_guards(callsite_runtime_all)

            arg_flags = self._edge_flags_from_guards_or_typename(
                guards=callee_guards_all,
                bindings=bindings,
                bitmask_groups=self.bitmask_groups
            )
            for v in arg_flags.values():
                if v.get("bundle_key"):
                    bitmask_seen_keys.add(v["bundle_key"])
            
            edges_out.append({
                "from_usr": usrs[i],
                "to_usr": usrs[i + 1],
                "call_kind": call_kind,
                "callback_param": callback_param_for_edge,
                "callsite": None,
                "param_bindings": bindings,
                "arg_flags": arg_flags,
                "callsite_guards": {
                    "runtime": callsite_runtime,
                    "compile_time": compile_time_macros
                }
            })

        # 4) 根据看到的 bitmask key 构建 bundle
        bitmask_bundles = []
        for key in bitmask_seen_keys:
            g = next((x for x in self.bitmask_groups if x.get("key") == key), {"key": key})
            bitmask_bundles.append({
                "key": key,
                "bind_param": [],
                "values": [
                    v.get("name") for v in (g.get("value") or [])
                    if isinstance(v, dict) and v.get("name")
                ],
                "composed": g.get("composed") or {},
                "suggest_default": None,
                "bit_width": g.get("bit_width_hint")
            })

        for i, sig in enumerate(sigs_seq):
            self._annotate_resources_ownership(nodes_out[i], sig)
        
        external_chain = [
            node["name"]
            for node in nodes_out
            if node.get("visibility") == "external"
        ]

        plan = {
            "chain":{
                "id": "->".join(name_chain),
                "nodes": nodes_out,
                "edges": edges_out,
            },
            "external_chain": external_chain,
            "bitmask_bundles": bitmask_bundles,
            "lifecycle_plan": lifcycle,
            "externals": self._collect_externals(),
            "harness_hint": {
                "param_defaults": self._collect_param_defaults(edges_out)
            },
        }

        # 5) 接入sourcecode extractor 提取实现细节
        impl_extractor = ImplementationExtractor(
            self.ccdb, enrich_args_fn=enrich_clang_args_for_analysis,
            include_headers=self.include_headers, with_leading_comment=True,
            dedent=True, context_lines=0
        )
        plan = impl_extractor.extract_for_plan_nodes(plan)

        return plan

# an API to use Aggregator to build harness plan
def aggregate_for_chain(name_chain: List[str], 
                        ccdb_path: str, 
                        include_headers: bool = False, 
                        system_includes: bool = False,
                        bitmask_require_op: bool = True,
                        max_guards_per_node: int = 4,
                        vendor_prefixes: Optional[List[str]] = None,
                        infer_vendor_prefixes: bool = True,
                        vendor_prefix_threshold: float = 0.25,
                        min_vendor_len: int = 2
                        ) -> Dict:
    ag = Aggregator(ccdb_path=ccdb_path,
                     include_headers=include_headers,
                     system_includes=system_includes,
                     bitmask_require_op=bitmask_require_op,
                     max_guards_per_node=max_guards_per_node,
                     vendor_prefixes=vendor_prefixes,
                     infer_vendor_prefixes=infer_vendor_prefixes,
                     vendor_prefix_threshold=vendor_prefix_threshold,
                     min_vendor_len=min_vendor_len)
    
    ag.scan_project_for_call_chain(name_chain=name_chain)

    return ag.build_plan_for_chain(name_chain=name_chain)

if __name__ == "__main__":
    plan = aggregate_for_chain(
        # name_chain= ["xmllintMain", "xmlCtxtSetResourceLoader","xmllintResourceLoader"],
        name_chain = ['xmlTextReaderSchemaValidate', 'xmlTextReaderSchemaValidateInternal', 'xmlSchemaParse', 'xmlSchemaParseNewDocWithContext', 'xmlSchemaParseSimpleType', 'xmlGetNoNsProp', 'xmlNodeGetContent'],
        ccdb_path="/root/libxml2/bear_build/compile_commands.json",
        include_headers=False,
        system_includes=False,
        bitmask_require_op=True,
        max_guards_per_node=4
    )

    print(plan)
    print(json.dumps(plan, indent=2))
