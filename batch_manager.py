import json
import uuid
import os

from typing import List, Dict, Any

class Batch:
    def __init__(self, batch_id: str=None ,target_func: str=None):
        self.batch_id = str(uuid.uuid4())
        self.target_func = target_func
        self.json_path = ""
        self.harness_info = {}

    def save_metadata(self, filepath="./batch_metadata/") -> Any:
        save_path = os.path.join(filepath, f"{self.batch_id}.json")
        os.makedirs(filepath, exist_ok=True)

        metadata = {
            "batch_id": self.batch_id,
            "target_func": self.target_func,
            "harness_info": self.harness_info
        }

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4)

        self.json_path = save_path

        return self.json_path
    
    @classmethod
    def load_metadata(cls, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        batch = cls(
                batch_id = metadata["batch_id"],
                target_func = metadata["tareget_func"]
            )
        batch.harness_info