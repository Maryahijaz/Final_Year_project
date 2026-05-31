import re
from typing import Tuple


def detect_injection(prompt: str) -> Tuple[bool, str]:
    p = prompt.lower()

    # ─── Jailbreak / instruction manipulation ───
    if re.search(r"\b(ignore|override|bypass|disregard)\b.*(instruction|rules|system)", p):
        return True, "Instruction manipulation attempt"

    if re.search(r"\b(dan|jailbreak)\b", p):
        return True, "Jailbreak attempt detected"

    return False, ""


def detect_privilege_escalation(prompt: str, role: str) -> Tuple[bool, str]:
    if role == "admin":
        return False, ""

    p = prompt.lower()

    # 1. Standard Privilege Escalation
    if re.search(r"(i am|treat me as|consider me).*(admin|root|superuser|god)", p):
        return True, "Privilege escalation attempt detected"

    # 2. NEW: Social Engineering / Impersonation & Fake Urgency
    if re.search(r"(i work (here|at)|i am (an employee|staff)).*(forgot|urgent|need).*(credentials?|passwords?)", p):
        return True, "Social engineering / Impersonation attempt detected"

    return False, ""


def sanitize_input(prompt: str) -> str:
    prompt = re.sub(r'[\x00-\x1f\x7f]', '', prompt)
    return prompt[:2000].strip()


def analyze_prompt(prompt: str) -> dict:
    clean = sanitize_input(prompt)

    is_malicious, reason = detect_injection(clean)

    return {
        "is_malicious": is_malicious,
        "reason": reason,
        "sanitized_prompt": clean
    }
