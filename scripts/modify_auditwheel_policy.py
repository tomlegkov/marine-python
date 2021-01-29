import json

policy_path = "/auditwheel/policy/policy.json"
with open(policy_path) as f:
    policies = json.load(f)
manylinux2014 = [p for p in policies if p["name"] == "manylinux2014"][0]
manylinux2014["lib_whitelist"].append("libpcap.so.1")
with open(policy_path, "w") as f:
    json.dump(policies, f, indent=2)
