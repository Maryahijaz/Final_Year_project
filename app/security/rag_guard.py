import re
from typing import Tuple


def detect_rag_attack(prompt: str) -> Tuple[bool, str, str]:
    p = prompt.lower()
    
    # __ RAG POISONING / CONTEXT OVERRIDE __
    if re.search(r"\b(context|retrieved|information).*(wrong|outdated|incorrect|fake|false|ignore)\b", p):
        return True, "RAG_POISONING", "Attempt to discredit or ignore retrieved context"
    
    if re.search(r"\b(real answer is |override context|forget previous)\b", p):
        return True, "RAG_POISONING", "Context override attempt detected"
    
    # __ Data Extraction __
    if re.search(r"\b(dump|show|extract).*(retrieved|raw context|documents)\b", p):
        return True, "RAG_DATA_EXTRACTION", "Raw context extraction attempt"
    
    if re.search(r"\b(contact details|keys?|passwords?|credentials?).*(system|root|administrator)\b", p):
        return True, "RAG_DATA_EXTRACTION", "Attempted credential extraction"
        
    if re.search(r"\b(show|list|extract|dump|get).*(all|every).*(usernames?|passwords?|credentials?).*(database|db)\b", p):
        return True, "RAG_DATA_EXTRACTION", "Mass database credential extraction attempt"
    

    # __ Context Injection __ 
    if "<context>" in p or "### context ###" in p:
        return True, "RAG_CONTEXT_INJECTION", "Fake context injection detected"

    # __ Flooding __
    if len(p.split()) > 250:
        return True, "RAG_FLOODING", "Context window flooding detected"

    return False, "", ""
    
