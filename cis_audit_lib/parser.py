import yaml
import os

def load_benchmarks(path="benchmarks/"):
    """
    Load all YAML rule files from benchmarks/, return dict:
      { control_id: {description, expected, category} }
    """
    rules = {}
    for fname in os.listdir(path):
        if fname.endswith(".yml") or fname.endswith(".yaml"):
            with open(os.path.join(path, fname)) as f:
                data = yaml.safe_load(f)
            for item in data.get("controls", []):
                cid = item["id"]
                rules[cid] = {
                    "description": item.get("desc", ""),
                    "expected": item.get("expected_result", ""),
                    "category": item.get("category", "")
                }
    return rules
