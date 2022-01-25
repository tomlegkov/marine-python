import json
from typing import List, TypedDict


class Policy(TypedDict):
    name: str
    lib_whitelist: List[str]
    # There are more fields but they don't concern us

policy_path = "/auditwheel/policy/manylinux-policy.json"

with open(policy_path) as f:
    policies: List[Policy] = json.load(f)

for policy in policies:
    policy["lib_whitelist"].append("libpcap.so.1")

with open(policy_path, "w") as f:
    json.dump(policies, f, indent=2)
