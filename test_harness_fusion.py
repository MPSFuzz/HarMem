import json, sys, glob, os
sys.path.insert(0, '/root/auto_harness')

from src.harness_memory.harness_fusion import HarnessFusion, extract_calls, jaccard_similarity

harness_dir = "src/harness/20260721_101253"
harness_c = f"{harness_dir}/20260721_101253_xmlSchemaValidatorPopElem.c"
root_api = "xmlSchemaValidateOneElement"
keywords = ["xml"]

print("=== Step 0: Clean old fusion.json ===")
old_fusion = f"{harness_dir}/harness_fusion.json"
if os.path.exists(old_fusion):
    os.rename(old_fusion, old_fusion + ".bak")
    print("  moved to .bak")

print(f"\n=== Step 1: Bootstrap fusion from {harness_dir} memory files ===")
fusion = HarnessFusion.from_harness_dir(root_api, harness_dir, keywords=keywords, threshold=0.85)
print(f"  tolerance_left: {fusion.tolerance_left}")
print(f"  accepted ({len(fusion.accepted)}):")
for a in fusion.accepted:
    print(f"    #{a['id']}: {os.path.basename(a['harness_path'])}  calls={len(a['calls'])}  reached_target={a.get('reached_target','?')}")

if len(fusion.accepted) >= 2:
    a1 = set(fusion.accepted[0]["calls"])
    a2 = set(fusion.accepted[1]["calls"])
    print(f"\n=== Step 2: Jaccard between bootstrapped harnesses ===")
    print(f"  accepted#1 ↔ accepted#2: {jaccard_similarity(a1, a2):.3f}")

print(f"\n=== Step 3: Evaluate current harness as new upgrade ===")
new_calls = extract_calls(harness_c, keywords)
print(f"  current harness calls: {len(new_calls)}")

# Check against each accepted
for a in fusion.accepted:
    acc_calls = set(a["calls"])
    sim = jaccard_similarity(new_calls, acc_calls)
    print(f"  current ↔ #{a['id']} ({os.path.basename(a['harness_path'])}): jaccard={sim:.3f}  {'REJECTED' if sim > 0.85 else 'ACCEPTED'}")

result = fusion.evaluate_new_harness(harness_c, reached_target=True)
print(f"\n  final verdict: {'ACCEPTED' if result else 'REJECTED'}")
print(f"  accepted total: {len(fusion.accepted)}")

fusion.save(f"{harness_dir}/harness_fusion.json")
print(f"\nSaved to {harness_dir}/harness_fusion.json")
