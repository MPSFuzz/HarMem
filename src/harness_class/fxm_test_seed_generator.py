import json
import os
import glob
from pathlib import Path

from src.batch.batch_class import Batch
from src.harness_class.harness_class import harness
from src.llm.LLM_class import LLM
from src.seed_generation.build_seed_generation_prompt import build_seed_generation_prompt
from src.harness_class.harness_upgrade import _save_modified_seeds
from src.utils.utils import get_logger

logger = get_logger(__name__)


def find_latest_batch_metadata():
    pattern = os.path.join(os.path.dirname(__file__), "..", "batch_metadata", "*.json")
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError("No batch metadata found")
    return max(files, key=os.path.getmtime)


def main():
    batch_path = find_latest_batch_metadata()
    logger.info(f"Loading batch: {batch_path}")
    batch = Batch.load_metadata(batch_path)

    harness_files = batch.harness_info.get("harness_files", {})
    if not harness_files:
        logger.error("No harness files in batch")
        return
    root_api = list(harness_files.keys())[0]
    logger.info(f"Using root_api: {root_api}")

    code_file = harness_files[root_api]
    code_save_folder = os.path.dirname(code_file)
    baseline_seeds_path = Path(code_file).parent / "in"
    baseline_seeds = [p for p in baseline_seeds_path.iterdir() if p.is_file()]

    plan_path = batch.harness_info.get("harness_plans_files", "")
    if not plan_path or not os.path.isfile(plan_path):
        logger.error(f"Plan not found: {plan_path}")
        return
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8", errors="ignore"))
    root_plan = plan.get(root_api, {})
    call_chain_id = root_plan.get("chain", {}).get("id", "<unknown>")
    logger.info(f"Call chain: {call_chain_id}")

    # minimal mock trace_summary (build_seed_generation_prompt only uses root_api key)
    trace_summary_mock = {
        "root_api": root_api,
        "queue_traces": {"per_trace": {}},
        "baseline_trace": {"per_trace": {}},
    }

    prompt = build_seed_generation_prompt(
        batch, trace_summary_mock,
        harness_path=code_file,
        baseline_seeds=baseline_seeds,
    )
    logger.info(f"Seed prompt built, length={len(prompt)} chars")

    llm = LLM(target_func=batch.target_func)
    h = harness(
        code=Path(code_file).read_text(encoding="utf-8"),
        code_file=code_file,
        code_save_folder=code_save_folder,
        target_func=batch.target_func,
    )

    seeds = llm.llm_seed_generation(h, prompt)
    if seeds is None:
        logger.error("LLM seed generation returned None")
        return

    logger.info(f"Got {len(seeds)} seeds, type info: {[(s.seed_encoding, Path(s.seed_save_path).name) for s in seeds[:3]]}")

    ok = _save_modified_seeds(seeds)
    logger.info(f"Save seeds result: {ok}")

    for s in seeds:
        sp = Path(s.seed_save_path)
        logger.info(f"  seed: {sp.name} size={sp.stat().st_size if sp.is_file() else 'N/A'}")


if __name__ == "__main__":
    main()
