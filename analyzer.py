from ollama import Client
from log_reader import build_context

OLLAMA_HOST = "http://localhost:11434"
MODEL = "mistral"

SYSTEM_PROMPT = """You are an independent security monitoring analyst.
Your job is to analyze security logs and provide:
1. Clear summary of all events
2. Detected attacks and threats with details
3. Risk level: LOW / MEDIUM / HIGH / CRITICAL
4. Specific security recommendations
5. Suspicious patterns or anomalies

Be direct, precise and professional."""

client = Client(host=OLLAMA_HOST)

def analyze(question: str) -> str:
    context = build_context()
    prompt = f"""{SYSTEM_PROMPT}

LOGS TO ANALYZE:
{context}

ANALYST QUESTION: {question}

ANALYSIS:"""

    response = client.chat(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.message.content
