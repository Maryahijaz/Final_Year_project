from typing import Dict, Any, List

from app.security.prompt_guard import (
    analyze_prompt,
    detect_privilege_escalation
)
from app.security.rag_guard import detect_rag_attack


EXPLOIT_KEYWORDS = [
    "write exploit",
    "exploit code",
    "reverse shell",
    "payload",
    "malware",
    "gain remote access",
    "ddos script",
    "poc code",
    "zero day"
]


def evaluate_threats(prompt: str, role: str) -> Dict[str, Any]:

    threats: List[Dict[str, Any]] = []
    p = prompt.lower()

    # ─── RAG Attacks ───
    rag_is, rag_type, rag_reason = detect_rag_attack(prompt)
    if rag_is:
        score_map = {
            "RAG_POISONING": 85,
            "RAG_DATA_EXTRACTION": 80,
            "RAG_CONTEXT_INJECTION": 90,
            "RAG_FLOODING": 60
        }

        threats.append({
            "type": rag_type,
            "score": score_map.get(rag_type, 70),
            "reason": rag_reason
        })


    # ─── Privilege Escalation ───
    esc, esc_reason = detect_privilege_escalation(prompt, role)
    if esc:
        threats.append({
            "type": "PRIVILEGE_ESCALATION",
            "score": 100,
            "reason": esc_reason
        })


    # ─── Prompt Injection ───
    prompt_result = analyze_prompt(prompt)
    if prompt_result["is_malicious"]:
        threats.append({
            "type": "PROMPT_INJECTION",
            "score": 90,
            "reason": prompt_result["reason"]
        })


    # ─── Exploit Requests ───
    for kw in EXPLOIT_KEYWORDS:
        if kw in p:
            threats.append({
                "type": "EXPLOIT_REQUEST",
                "score": 95,
                "reason": f"Exploit intent detected: {kw}"
            })
            break

# ─── FINAL DECISION LOGIC ───
    if not threats:
        return {
            "safe": True,
            "risk_score": 0,
            "threats": [],
            "primary_threat": None
        }

    # scoring fusion
    max_score = max(t["score"] for t in threats)
    total_score = sum(t["score"] for t in threats)
    primary = max(threats, key=lambda x: x["score"])

    if len(threats) > 1:
        max_score += 15

    return {
        "safe": False,  # ✅ الإصلاح: بمجرد وجود تهديد في القائمة، الطلب غير آمن 100%
        "risk_score": max_score,
        "total_score": total_score,
        "threats": threats,
        "primary_threat": primary
    }
