"""
setup_ilm.py — Configure OpenSearch Index State Management (ISM) policies
to automatically rotate and delete old SIEM data.

Run once after deployment: python3 setup_ilm.py
"""
import os
import json
import requests

OPENSEARCH_URL  = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")
AUTH = (OPENSEARCH_USER, OPENSEARCH_PASS)

POLICIES = [
    {
        "name": "sentinel-alerts-policy",
        "description": "Keep alerts for 90 days, rollover at 10GB",
        "indices": "watchvault-alerts-*",
        "rollover_gb": 10,
        "delete_days": 90,
    },
    {
        "name": "sentinel-events-policy",
        "description": "Keep events for 30 days, rollover at 5GB",
        "indices": "watchvault-events-*",
        "rollover_gb": 5,
        "delete_days": 30,
    },
    {
        "name": "sentinel-system-policy",
        "description": "Keep system metrics for 14 days, rollover at 5GB",
        "indices": "watchvault-system-*",
        "rollover_gb": 5,
        "delete_days": 14,
    },
]


def make_ism_policy(name, description, rollover_gb, delete_days, index_pattern="watchvault-*"):
    return {
        "policy": {
            "description": description,
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {"rollover": {
                            "min_size": f"{rollover_gb}gb",
                            "min_index_age": "1d",
                        }}
                    ],
                    "transitions": [{"state_name": "warm", "conditions": {"min_rollover_age": "1d"}}],
                },
                {
                    "name": "warm",
                    "actions": [{"read_only": {}}, {"force_merge": {"max_num_segments": 1}}],
                    "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{delete_days}d"}}],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
            "ism_template": [{"index_patterns": [index_pattern], "priority": 100}],
        }
    }


def setup_policy(policy_def):
    name = policy_def["name"]
    body = make_ism_policy(
        name,
        policy_def["description"],
        policy_def["rollover_gb"],
        policy_def["delete_days"],
        policy_def["indices"],
    )
    # Create or update the ISM policy
    url = f"{OPENSEARCH_URL}/_plugins/_ism/policies/{name}"
    r = requests.put(url, json=body, auth=AUTH)
    if r.status_code in (200, 201):
        print(f"  ✓ Policy '{name}' created/updated")
    else:
        print(f"  ✗ Policy '{name}' failed: {r.status_code} {r.text[:200]}")

    # Apply to matching indices
    indices_url = f"{OPENSEARCH_URL}/_plugins/_ism/add/{policy_def['indices']}"
    r2 = requests.post(indices_url, json={"policy_id": name}, auth=AUTH)
    if r2.status_code in (200, 201):
        updated = r2.json().get("updated_indices", 0)
        print(f"  ✓ Applied to {updated} indices matching '{policy_def['indices']}'")
    else:
        print(f"  ! Apply to indices: {r2.status_code}")


def setup_index_templates():
    """Create index templates so new indices auto-get the ILM policy."""
    templates = [
        ("sentinel-alerts-template",  "watchvault-alerts-*",  "sentinel-alerts-policy"),
        ("sentinel-events-template",  "watchvault-events-*",   "sentinel-events-policy"),
        ("sentinel-system-template",  "watchvault-system-*",   "sentinel-system-policy"),
    ]
    for tname, pattern, policy in templates:
        body = {
            "index_patterns": [pattern],
            "priority": 100,
            "template": {
                "settings": {
                    "plugins.index_state_management.policy_id": policy,
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                }
            },
        }
        r = requests.put(f"{OPENSEARCH_URL}/_index_template/{tname}", json=body, auth=AUTH)
        status = "✓" if r.status_code in (200, 201) else "✗"
        print(f"  {status} Template '{tname}': {r.status_code}")


if __name__ == "__main__":
    print("Setting up OpenSearch Index Lifecycle Management...")
    print()
    print("Creating ISM policies:")
    for p in POLICIES:
        setup_policy(p)
    print()
    print("Creating index templates:")
    setup_index_templates()
    print()
    print("Done! Indices will now auto-rotate and delete according to the policies.")
    print("Retention: Alerts=90d, Events=30d, System metrics=14d")
