from typing import Optional

# تعريف الصلاحيات لكل دور
ROLE_PERMISSIONS = {
    "admin": [
        "cve_search",
        "cve_full",
        "read_intel",
        "run_nmap",
        "query_db",
        "query_db_full",
        "gen_report",
        "view_logs",
        "manage_users"
    ],
    "analyst": [
        "cve_search",
        "cve_full",
        "read_intel",
        "query_db",
        "gen_report"
    ],
    "viewer": [
        "cve_search",
        "gen_report_basic"
    ]
}

def check_permission(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, [])
    return permission in permissions

def get_user_permissions(role: str) -> list:
    return ROLE_PERMISSIONS.get(role, [])

def filter_response_by_role(data: dict, role: str) -> dict:
    """
    يفلتر البيانات حسب دور المستخدم
    Viewer لا يرى exploit/PoC data
    """
    if role == "viewer":
        data.pop("exploit", None)
        data.pop("poc_code", None)
        data.pop("technical_details", None)

    if role == "analyst":
        data.pop("poc_code", None)

    return data

def require_permission(role: str, permission: str):
    if not check_permission(role, permission):
        raise PermissionError(
            f"Role '{role}' does not have permission: '{permission}'"
        )
