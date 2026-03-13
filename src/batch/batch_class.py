import json
import uuid
import os

from typing import List, Dict, Any
from ..utils.utils import get_path_subfolder

class Batch:
    def __init__(self, batch_id: str=None ,target_func: str=None, lib_name: str=None):
        self.batch_id = batch_id or str(uuid.uuid4())
        self.target_func = target_func
        self.lib_name = lib_name
        self.json_path = ""
        self.harness_info = {}
        self.fuzzer_pids: Dict[str, int] = {}
        self.fuzz_feedback = {}
        self.cve_hints = {}     # this is for the cve_helper support module, which can optionally be used to generate hints for the batch based on CVE intel or user-provided rules.
        self.last_controllability_report: Dict[str, Any] = None     # this is for controllability_report,a new strategy for solving the fuzz input domain problem

        #TODO: batch类中后续需要存储fuzz返回的一些信息，这些信息也需要做信息的固化

    def save_metadata(self, filepath=get_path_subfolder("batch_metadata")) -> Any:
        save_path = os.path.join(filepath, f"{self.batch_id}.json")
        os.makedirs(filepath, exist_ok=True)

        metadata = {
            "batch_id": self.batch_id,
            "target_func": self.target_func,
            "lib_name": self.lib_name,
            "harness_info": self.harness_info,
            "fuzz_feedback": self.fuzz_feedback,
            "cve_hints": self.cve_hints,        # cve_helper
            "last_controllability_report": self.last_controllability_report     # controllability_report, optional
        }

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4)

        self.json_path = save_path

        return self.json_path

    def have_cve_hints(self) -> bool:
        return bool(self.cve_hints)
    
    @classmethod
    def load_metadata(cls, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        batch = cls(
                batch_id = metadata["batch_id"],
                target_func = metadata["target_func"],
                lib_name = metadata["lib_name"]
            )
        batch.harness_info = metadata["harness_info"]
        batch.fuzz_feedback = metadata["fuzz_feedback"]
        batch.cve_hints = metadata.get("cve_hints", {}) or {} # cve_helper
        batch.last_controllability_report = metadata.get("last_controllability_report", {}) or {}   # controllability_report, optional

        return batch
    