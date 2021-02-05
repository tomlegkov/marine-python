import json
from typing import List, TypedDict


class Policy(TypedDict):
    name: str
    lib_whitelist: List[str]
    # There are more fields but they don't concern us


policy_path = "/auditwheel/policy/policy.json"
with open(policy_path) as f:
    policies: List[Policy] = json.load(f)
[manylinux2014] = [p for p in policies if p["name"] == "manylinux2014"]
manylinux2014["lib_whitelist"].append("libpcap.so.1")
with open(policy_path, "w") as f:
    json.dump(policies, f, indent=2)
