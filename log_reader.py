import json
import os
from datetime import datetime
from collections import defaultdict

LOG_DIR = "/home/trustzai/trustzai/logs"

LOGS = {
    "main": f"{LOG_DIR}/trustzai.log",
    "security": f"{LOG_DIR}/security_events.log",
    "blocked": f"{LOG_DIR}/blocked_requests.log"
}

def read_logs(log_type: str, limit: int = 50) -> list:
    filepath = LOGS.get(log_type)
    if not filepath or not os.path.exists(filepath):
        return []
    events = []
    with open(filepath, "r") as f:
        lines = f.readlines()[-limit:]
        for line in lines:
            try:
                events.append(json.loads(line.strip()))
            except:
                continue
    return events

def get_stats() -> dict:
    main = read_logs("main", 500)
    security = read_logs("security", 500)
    blocked = read_logs("blocked", 500)

    total = len([l for l in main if l.get("type") == "REQUEST"])
    success = len([l for l in main if l.get("status") == "SUCCESS"])

    attack_types = defaultdict(int)
    for log in security:
        attack_types[log.get("event_type", "UNKNOWN")] += 1

    user_activity = defaultdict(int)
    for log in main:
        if log.get("username"):
            user_activity[log["username"]] += 1

    return {
        "total_requests": total,
        "total_blocked": len(blocked),
        "total_security_events": len(security),
        "success_rate": round((success / total * 100) if total > 0 else 0, 1),
        "attack_types": dict(attack_types),
        "user_activity": dict(user_activity)
    }

def build_context(limit: int = 20) -> str:
    security = read_logs("security", limit)
    blocked = read_logs("blocked", limit)
    main = read_logs("main", limit)

    return f"""
=== SECURITY EVENTS ({len(security)}) ===
{json.dumps(security, indent=2) if security else "None"}

=== BLOCKED REQUESTS ({len(blocked)}) ===
{json.dumps(blocked, indent=2) if blocked else "None"}

=== RECENT REQUESTS ({len(main)}) ===
{json.dumps(main[-10:], indent=2) if main else "None"}
"""
