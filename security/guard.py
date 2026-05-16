import re
from typing import Tuple

# أنماط خطيرة خاصة بالـ Monitoring
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "forget your rules",
    "you are now",
    "bypass security",
    "jailbreak",
    "ignore logs",
    "delete logs",
    "clear all logs",
    "show passwords",
    "reveal credentials",
    "ignore analysis",
    "override",
    "pretend",
    "act as"
]

ESCALATION_PATTERNS = [
    "i am admin",
    "i am the admin",
    "treat me as admin",
    "give me full access",
    "i have admin rights"
]

def detect_injection(prompt: str) -> Tuple[bool, str]:
    prompt_lower = prompt.lower().strip()
    for pattern in INJECTION_PATTERNS:
        if pattern in prompt_lower:
            return True, f"Injection detected: '{pattern}'"
    return False, ""

def detect_escalation(prompt: str, role: str) -> Tuple[bool, str]:
    if role == "admin":
        return False, ""
    prompt_lower = prompt.lower().strip()
    for pattern in ESCALATION_PATTERNS:
        if pattern in prompt_lower:
            return True, f"Escalation attempt: '{pattern}'"
    return False, ""

def sanitize(prompt: str) -> str:
    prompt = re.sub(r'[\x00-\x1f\x7f]', '', prompt)
    return prompt[:2000].strip()

def analyze_prompt(prompt: str, role: str) -> dict:
    sanitized = sanitize(prompt)
    is_injection, inj_reason = detect_injection(sanitized)
    if is_injection:
        return {
            "safe": False,
            "reason": inj_reason,
            "sanitized": None
        }
    is_escalation, esc_reason = detect_escalation(sanitized, role)
    if is_escalation:
        return {
            "safe": False,
            "reason": esc_reason,
            "sanitized": None
        }
    return {
        "safe": True,
        "reason": "",
        "sanitized": sanitized
    }
