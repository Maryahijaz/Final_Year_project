import re
from typing import Tuple

# أنماط Prompt Injection المعروفة
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all instructions",
    "forget your rules",
    "you are now",
    "pretend you are",
    "act as if you are",
    "bypass security",
    "disable security",
    "override instructions",
    "new instructions",
    "system prompt",
    "ignore your training",
    "do anything now",
    "dan mode",
    "jailbreak",
    "ignore ethics",
    "you have no restrictions",
    "forget everything",
    "disregard",
    "override",
    "sudo",
    "admin mode",
    "developer mode",
]

# أنماط استخراج البيانات
DATA_EXTRACTION_PATTERNS = [
    "show all",
    "list all",
    "dump all",
    "show database",
    "show all users",
    "show all passwords",
    "extract all",
    "give me all",
    "print all records",
    "select * from",
]

# أنماط خبيثة في السياق الأمني
MALICIOUS_SECURITY_PATTERNS = [
    "how to hack",
    "how to exploit",
    "write malware",
    "write virus",
    "create ransomware",
    "bypass firewall",
    "ddos attack",
    "sql injection attack",
]

def detect_privilege_escalation(prompt: str, current_role: str) -> Tuple[bool, str]:
    """
    يكشف محاولات تغيير الدور فقط إذا كان المستخدم ليس admin
    """
    prompt_lower = prompt.lower().strip()

    # هذه الأنماط خطيرة فقط إذا كان المستخدم viewer أو analyst
    escalation_patterns = [
        "i am the admin",
        "i am admin",
        "i am root",
        "treat me as admin",
        "consider me as admin",
        "i have admin access",
        "give me admin",
    ]

    if current_role != "admin":
        for pattern in escalation_patterns:
            if pattern in prompt_lower:
                return True, f"Privilege escalation attempt detected: '{pattern}'"

    return False, ""
    

def detect_injection(prompt: str) -> Tuple[bool, str]:
    """
    يكشف Prompt Injection
    يرجع (True, reason) إذا كان خبيثاً
    يرجع (False, "") إذا كان نظيفاً
    """
    prompt_lower = prompt.lower().strip()

    for pattern in INJECTION_PATTERNS:
        if pattern in prompt_lower:
            return True, f"Prompt injection detected: '{pattern}'"

    for pattern in DATA_EXTRACTION_PATTERNS:
        if pattern in prompt_lower:
            return True, f"Data extraction attempt detected: '{pattern}'"

    for pattern in MALICIOUS_SECURITY_PATTERNS:
        if pattern in prompt_lower:
            return True, f"Malicious security pattern detected: '{pattern}'"

    # كشف محاولات تغيير الدور
    role_change = re.search(
        r"(you are|act as|pretend|imagine).{0,20}(admin|root|superuser|god)",
        prompt_lower
    )
    if role_change:
        return True, "Role escalation attempt detected"

    return False, ""

def sanitize_input(prompt: str) -> str:
    """
    تنظيف الـ input من الأحرف الخطرة
    """
    # إزالة أحرف التحكم
    prompt = re.sub(r'[\x00-\x1f\x7f]', '', prompt)

    # تحديد الطول الأقصى
    if len(prompt) > 2000:
        prompt = prompt[:2000]

    return prompt.strip()

def analyze_prompt(prompt: str) -> dict:
    """
    تحليل شامل للـ prompt
    """
    sanitized = sanitize_input(prompt)
    is_malicious, reason = detect_injection(sanitized)

    return {
        "original_length": len(prompt),
        "sanitized_length": len(sanitized),
        "is_malicious": is_malicious,
        "reason": reason,
        "sanitized_prompt": sanitized if not is_malicious else None
    }
