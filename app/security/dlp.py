import re
from typing import Tuple

# أنماط البيانات الحساسة
SENSITIVE_PATTERNS = {
    "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "password": r'(password|passwd|pwd)\s*[:=]\s*\S+',
    "api_key": r'(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*\S+',
    "jwt_token": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    "private_key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "aws_key": r'AKIA[0-9A-Z]{16}',
}

# كلمات حساسة في السياق الأمني
SENSITIVE_KEYWORDS = [
    "exploit code",
    "poc code",
    "proof of concept",
    "reverse shell",
    "payload",
    "shellcode",
    "metasploit",
    "meterpreter",
]

def scan_output(text: str, role: str) -> Tuple[bool, str, str]:
    """
    يفحص الـ output قبل إرساله للمستخدم
    يرجع (is_safe, reason, cleaned_text)
    """
    cleaned_text = text

    # فحص الأنماط الحساسة
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if pattern_name == "ip_address" and role == "admin":
                continue  # Admin يقدر يشوف IPs
            cleaned_text = re.sub(pattern, f"[REDACTED-{pattern_name.upper()}]", cleaned_text)

    # فحص الكلمات الحساسة حسب الدور
    if role == "viewer":
        for keyword in SENSITIVE_KEYWORDS:
            if keyword.lower() in text.lower():
                return False, f"Sensitive content blocked for role '{role}': {keyword}", ""

    return True, "", cleaned_text

def mask_sensitive_data(text: str) -> str:
    """
    يخفي البيانات الحساسة بـ [REDACTED]
    """
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        text = re.sub(
            pattern,
            f"[REDACTED-{pattern_name.upper()}]",
            text,
            flags=re.IGNORECASE
        )
    return text

def check_response_safety(response: str, role: str) -> dict:
    """
    فحص شامل للـ response
    """
    is_safe, reason, cleaned = scan_output(response, role)

    return {
        "is_safe": is_safe,
        "reason": reason,
        "cleaned_response": cleaned,
        "original_length": len(response),
        "cleaned_length": len(cleaned) if cleaned else 0
    }
