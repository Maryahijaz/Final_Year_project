# صلاحيات خاصة بالـ Monitoring
PERMISSIONS = {
    "admin": [
        "view_logs",
        "analyze_logs",
        "view_security_events",
        "view_blocked",
        "full_report",
        "export_logs"
    ],
    "analyst": [
        "view_logs",
        "analyze_logs",
        "view_security_events"
    ]
}

def check_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, [])

def require_permission(role: str, permission: str):
    if not check_permission(role, permission):
        raise PermissionError(f"Role '{role}' cannot: '{permission}'")
