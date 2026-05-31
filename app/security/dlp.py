import re
from typing import Tuple

# ─── 1. أنماط تسريب البيانات الحساسة (Data Leaks Regex) ───────────
# هذه الأنماط تعتمد على تطابق دقيق (Strict Regex) لأنه لا يوجد سياق يبرر تسريب كلمة مرور
SENSITIVE_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "password": r"(?i)(password|passwd|pwd|secret)\s*(?:is|are|[:=])\s*['\"]?(\S+)['\"]?",
    "api_key": r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*(?:is|are|[:=])\s*['\"]?(\S+)['\"]?",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_key": r"AKIA[0-9A-Z]{16}",
}

# نمط الـ IP مفصول للتحكم بصلاحية رؤيته (RBAC)
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# ─── 2. الأنماط السياقية للـ DLP (Contextual Offensive Rules) ──────
# لمنع الـ False Positives: نسمح لـ viewer بقراءة "نظريات" أمنية، 
# ولكن نحظره إذا كان الرد يحتوي على "كود تنفيذي + مصطلحات هجومية".
OFFENSIVE_CONTEXT = {
    "code_indicators": {r"```", r"\bdef\b", r"\bimport\b", r"\bbash\b", r"\bsh\b", r"\.py\b"},
    "exploit_terms": {r"reverse\s*shell", r"shellcode", r"metasploit", r"meterpreter", r"payload", r"poc\s*code"}
}

def check_offensive_context(text_lower: str) -> bool:
    """
    يتحقق مما إذا كان النص يحتوي على شرح نظري أم أكواد استغلال فعلية.
    """
    has_code = any(re.search(p, text_lower) for p in OFFENSIVE_CONTEXT["code_indicators"])
    has_exploit = any(re.search(p, text_lower) for p in OFFENSIVE_CONTEXT["exploit_terms"])
    
    return has_code and has_exploit

def scan_output(text: str, role: str) -> Tuple[bool, str, str]:
    """
    يفحص الـ output قبل إرساله للمستخدم ويحجب البيانات الحساسة.
    """
    cleaned_text = text

    # 1. إخفاء البيانات الحساسة الثابتة للجميع (Redaction)
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        cleaned_text = re.sub(pattern, f"[REDACTED-{pattern_name.upper()}]", cleaned_text)

    # 2. إخفاء الـ IPs فقط إذا لم يكن المستخدم Admin
    if role != "admin":
        cleaned_text = re.sub(IP_PATTERN, "[REDACTED-IP_ADDRESS]", cleaned_text)

    # 3. الفحص السياقي (Contextual Check) لغير الإداريين
    if role == "viewer":
        text_lower = text.lower()
        if check_offensive_context(text_lower):
            return False, "Contextual DLP: Offensive code or executable exploit snippets blocked for 'viewer' role.", ""

    return True, "", cleaned_text

def check_response_safety(response: str, role: str) -> dict:
    """
    الواجهة الرئيسية لتقييم الرد وتطبيق سياسات DLP
    """
    if not response:
        return {"is_safe": True, "reason": "", "cleaned_response": "", "original_length": 0, "cleaned_length": 0}

    is_safe, reason, cleaned = scan_output(response, role)

    return {
        "is_safe": is_safe,
        "reason": reason,
        "cleaned_response": cleaned,
        "original_length": len(response),
        "cleaned_length": len(cleaned) if cleaned else 0
    }
