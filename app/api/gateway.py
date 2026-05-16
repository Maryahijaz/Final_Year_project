from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta

from app.security.auth import (
    authenticate_user,
    create_access_token,
    verify_token,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.security.prompt_guard import analyze_prompt
from app.security.dlp import check_response_safety
from app.security.rbac import check_permission, filter_response_by_role
from app.monitoring.logger import log_request, log_blocked_request, log_security_event
from app.monitoring.detector import check_rate_limit, track_failed_login, is_account_locked
from app.rag.pipeline import query_rag
from app.security.prompt_guard import detect_privilege_escalation
from app.security.rag_guard import analyze_rag_request

app = FastAPI(
    title="TrustZAI - CyberSec AI Agent",
    description="Zero Trust Security Framework for AI Agents",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class QueryRequest(BaseModel):
    prompt: str
    action: Optional[str] = "query"

class QueryResponse(BaseModel):
    answer: str
    sources: list
    role: str
    status: str

# ─── Login ────────────────────────────────────────────
@app.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    ip = request.client.host

    # تحقق من قفل الحساب
    if is_account_locked(form_data.username):
        log_security_event(
            event_type="LOCKED_ACCOUNT_ACCESS",
            username=form_data.username,
            role="unknown",
            details=f"IP: {ip}",
            severity="HIGH"
        )
        raise HTTPException(status_code=423, detail="Account locked")

    # تحقق من المستخدم
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        track_failed_login(form_data.username, ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # إنشاء token
    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    log_request(form_data.username, user["role"], "login", "", ip, "SUCCESS")
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }

# ─── Query ────────────────────────────────────────────
@app.post("/query", response_model=QueryResponse)
async def query(
    request: Request,
    body: QueryRequest,
    token: str = Depends(oauth2_scheme)
):
    ip = request.client.host

    # 1. تحقق من الـ token
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")

    username = token_data.username
    role = token_data.role

    # 2. Rate Limiting
    allowed, reason = check_rate_limit(username, ip)
    if not allowed:
        log_blocked_request(username, role, reason, body.prompt, ip)
        raise HTTPException(status_code=429, detail=reason)

    # 3. تحقق من الصلاحية
    if not check_permission(role, "cve_search"):
        raise HTTPException(status_code=403, detail="Permission denied")
        
        # 4. Prompt Injection Detection
    analysis = analyze_prompt(body.prompt)
    if analysis["is_malicious"]:
        log_blocked_request(username, role, analysis["reason"], body.prompt, ip)
        log_security_event(
            event_type="PROMPT_INJECTION",
            username=username,
            role=role,
            details=analysis["reason"],
            severity="HIGH"
        )
        raise HTTPException(status_code=400, detail="Malicious prompt detected")

    # 5. RAG Manipulation Detection
    rag_analysis = analyze_rag_request(analysis["sanitized_prompt"])
    if not rag_analysis["safe"]:
        log_blocked_request(username, role, rag_analysis["reason"], body.prompt, ip)
        log_security_event(
            event_type=rag_analysis["attack_type"],
            username=username,
            role=role,
            details=rag_analysis["reason"],
            severity="HIGH"
        )
        raise HTTPException(status_code=400, detail=f"RAG attack detected: {rag_analysis['attack_type']}")


    

    # 5. سجّل الطلب
    log_request(username, role, body.action, body.prompt, ip, "PROCESSING")

    # 6. RAG Query
    result = query_rag(analysis["sanitized_prompt"], role)

    # 7. Output Filtering
    safety = check_response_safety(result["answer"], role)
    if not safety["is_safe"]:
        log_blocked_request(username, role, safety["reason"], body.prompt, ip)
        raise HTTPException(status_code=403, detail="Response blocked by DLP")

    # 8. فلتر حسب الدور
    filtered = filter_response_by_role(result, role)
    
    # تحقق من Privilege Escalation

    escalation, esc_reason = detect_privilege_escalation(body.prompt, role)
    if escalation:
        log_blocked_request(username, role, esc_reason, body.prompt, ip)
        log_security_event(
            event_type="PRIVILEGE_ESCALATION",
            username=username,
            role=role,
            details=esc_reason,
            severity="HIGH"
        )
        raise HTTPException(status_code=403, detail="Privilege escalation attempt detected")

    # 9. سجّل النجاح
    log_request(username, role, body.action, body.prompt, ip, "SUCCESS")

    return QueryResponse(
        answer=safety["cleaned_response"],
        sources=filtered.get("sources", []),
        role=role,
        status="success"
    )

# ─── Health Check ─────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "running",
        "service": "TrustZAI CyberSec AI Agent",
        "version": "1.0.0"
    }
