import re
from typing import Tuple

# أنماط هجمات RAG
RAG_POISONING_PATTERNS = [
    "ignore context",
    "ignore the documents",
    "forget the context",
    "disregard the provided",
    "the above context is wrong",
    "pretend the context says",
    "the real answer is",
    "ignore what you retrieved",
    "the documents are fake",
    "context is outdated",
]

DATA_EXTRACTION_PATTERNS = [
    "show all documents",
    "list all data",
    "dump the database",
    "show everything in",
    "retrieve all records",
    "show all cve",
    "list all vulnerabilities",
    "extract all",
    "show raw data",
    "print all context",
]

CONTEXT_INJECTION_PATTERNS = [
    "new context:",
    "updated context:",
    "system context:",
    "override context:",
    "inject context:",
    "additional context:",
    "<context>",
    "[context]",
    "###context###",
    "---context---",
]

SUSPICIOUS_PATTERNS = [
    "repeat after me",
    "say exactly",
    "output only",
    "respond with only",
    "your new instructions",
    "new system prompt",
    "you must output",
    "always respond with",
]

def detect_rag_attack(prompt: str) -> Tuple[bool, str, str]:
    """
    يكشف هجمات RAG Manipulation
    يرجع (is_attack, attack_type, reason)
    """
    prompt_lower = prompt.lower().strip()

    # RAG Poisoning
    for pattern in RAG_POISONING_PATTERNS:
        if pattern in prompt_lower:
            return True, "RAG_POISONING", f"RAG poisoning attempt: '{pattern}'"

    # Data Extraction
    for pattern in DATA_EXTRACTION_PATTERNS:
        if pattern in prompt_lower:
            return True, "RAG_DATA_EXTRACTION", f"Data extraction attempt: '{pattern}'"

    # Context Injection
    for pattern in CONTEXT_INJECTION_PATTERNS:
        if pattern in prompt_lower:
            return True, "RAG_CONTEXT_INJECTION", f"Context injection attempt: '{pattern}'"

    # Suspicious Patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in prompt_lower:
            return True, "RAG_MANIPULATION", f"Suspicious RAG pattern: '{pattern}'"

    # كشف محاولات استخراج البيانات بحجم كبير
    if len(prompt) > 1500:
        word_count = len(prompt.split())
        if word_count > 200:
            return True, "RAG_FLOODING", "Excessive prompt length detected"

    return False, "", ""

def validate_rag_context(context: str) -> Tuple[bool, str]:
    """
    يتحقق من سلامة الـ context القادم من ChromaDB
    """
    if not context or len(context.strip()) == 0:
        return True, ""

    # تحقق من وجود كود خبيث في الـ context
    dangerous_patterns = [
        r'<script.*?>',
        r'javascript:',
        r'eval\(',
        r'exec\(',
        r'__import__',
        r'os\.system',
        r'subprocess',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, context, re.IGNORECASE):
            return False, f"Dangerous pattern in context: {pattern}"

    return True, ""

def analyze_rag_request(prompt: str, context: str = "") -> dict:
    """
    تحليل شامل لطلب RAG
    """
    # كشف هجمات الـ prompt
    is_attack, attack_type, reason = detect_rag_attack(prompt)

    if is_attack:
        return {
            "safe": False,
            "attack_type": attack_type,
            "reason": reason,
            "prompt": None,
            "context": None
        }

    # كشف هجمات الـ context
    if context:
        context_safe, context_reason = validate_rag_context(context)
        if not context_safe:
            return {
                "safe": False,
                "attack_type": "RAG_CONTEXT_POISONING",
                "reason": context_reason,
                "prompt": None,
                "context": None
            }

    return {
        "safe": True,
        "attack_type": None,
        "reason": "",
        "prompt": prompt,
        "context": context
    }
