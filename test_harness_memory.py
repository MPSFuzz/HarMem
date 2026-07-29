import json, sys
sys.path.insert(0, '/root/auto_harness')

from src.harness_memory.harness_memory import HarnessMemory, cross_harness_analysis

batch_path = "src/batch_metadata/06f91e4b-c5f0-4cc9-bd95-877f9440e6be.json"
plan_path = "src/harness_plans/xmlSchemaValidatorPopElem_plans.json"

memories = []
for root_api in ["xmlSchemaValidateOneElement", "xmlSchemaValidateStream"]:
    mem = HarnessMemory.from_batch_and_plan(batch_path, plan_path, root_api)
    if not mem:
        print(f"SKIP {root_api}: no data")
        continue
    print(f"\n=== {root_api} ===")
    print(f"  expected: {' -> '.join(mem.iterations[0]['expected_chain'])}")
    print(f"  metrics: cover={mem.iterations[0]['metrics']['coverage']}% dist={mem.iterations[0]['metrics']['min_distance']:.0f} crashes={mem.iterations[0]['metrics']['crashes']}")

    # derived trace_summary per harness (let code derive gap from actual_chain)
    trace_summary = {"format": "derived"}
    if root_api == "xmlSchemaValidateOneElement":
        trace_summary["actual_chain"] = [
            {"func": "xmlSchemaValidateOneElement", "reach_rate": 0.95},
            {"func": "xmlSchemaVStart",            "reach_rate": 0.72},
            {"func": "xmlSchemaValidatorPopElem",  "reach_rate": 0.12}
        ]
        trace_summary["marker_hit"] = {"xmlschemas.c:23339": 0.035, "xmlschemas.c:23390": 0.012}
    elif root_api == "xmlSchemaValidateStream":
        trace_summary["actual_chain"] = [
            {"func": "xmlSchemaValidateStream",          "reach_rate": 1.0},
            {"func": "xmlSchemaValidateStreamInternal",  "reach_rate": 0.85},
            {"func": "xmlSchemaVStart",            "reach_rate": 0.68},
            {"func": "xmlSchemaValidatorPopElem",  "reach_rate": 0.09}
        ]
        trace_summary["marker_hit"] = {"xmlschemas.c:23339": 0.031, "xmlschemas.c:23390": 0.010}

    mem.populate_trace_data(0, trace_summary)

    actual = " -> ".join(f"{e['func']}({e['reach_rate']*100:.0f}%)" for e in mem.iterations[0]["actual_chain"])
    print(f"  actual:   {actual}")
    gap = mem.iterations[0]["gap"]
    print(f"  gap: {gap['broken_edge']}  furthest={gap['furthest_hit']}")
    print(f"  conclusion: {mem.conclusion}")

    mem.save(f"src/harness_memory_data/{root_api}_harness_memory.json")
    memories.append(mem)

# cross-harness analysis
print("\n=== cross_harness_analysis ===")
result = cross_harness_analysis(memories)
print(json.dumps(result, indent=2, ensure_ascii=False))
