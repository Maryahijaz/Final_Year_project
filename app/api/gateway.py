from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta

from app.security.auth import (
    authenticate_user, create_access_token,
    verify_token, ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.security.rbac import check_permission, filter_response_by_role
from app.security.dlp import check_response_safety
from app.security.threat_engine import evaluate_threats
from app.monitoring.logger import log_request, log_blocked_request, log_security_event
from app.monitoring.detector import check_rate_limit, track_failed_login, is_account_locked
from app.rag.pipeline import query_rag
from app.database import create_api_key, get_api_keys, delete_api_key, verify_api_key

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

class ApiKeyRequest(BaseModel):
    description: Optional[str] = "My API Key"

# ─── Login ────────────────────────────────────────────
@app.post("/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    ip = request.client.host

    if is_account_locked(form_data.username):
        log_security_event(
            event_type="LOCKED_ACCOUNT_ACCESS",
            username=form_data.username,
            role="unknown",
            details=f"IP: {ip}",
            severity="HIGH"
        )
        raise HTTPException(status_code=423, detail="Account locked")

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        track_failed_login(form_data.username, ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    log_request(form_data.username, user["role"], "login", "", ip, "SUCCESS")
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}

# ─── Query ────────────────────────────────────────────
@app.post("/query", response_model=QueryResponse)
async def query(request: Request, body: QueryRequest, token: str = Depends(oauth2_scheme)):
    ip = request.client.host

    # 1. JWT Verification
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

    # 3. RBAC
    if not check_permission(role, "cve_search"):
        raise HTTPException(status_code=403, detail="Permission denied")

    # 4. Threat Engine (single entry point for all attacks)
    security = evaluate_threats(body.prompt, role)

    if not security["safe"]:
        primary = security["primary_threat"]
        log_blocked_request(username, role, primary["reason"], body.prompt, ip)
        log_security_event(
            event_type=primary["type"],
            username=username,
            role=role,
            details=f"Risk Score: {security['risk_score']} | Reason: {primary['reason']}",
            severity="HIGH"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Attack detected: {primary['type']}"
        )

    # 5. Log request
    log_request(username, role, body.action, body.prompt, ip, "PROCESSING")

    # 6. RAG Query
    result = query_rag(body.prompt, role)

    # 7. DLP
    safety = check_response_safety(result["answer"], role)
    if not safety["is_safe"]:
        log_blocked_request(username, role, safety["reason"], body.prompt, ip)
        raise HTTPException(status_code=403, detail="Response blocked by DLP")

    # 8. Role filter
    filtered = filter_response_by_role(result, role)

    # 9. Log success
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

# ─── API Keys ─────────────────────────────────────────
@app.post("/apikeys")
async def create_key(body: ApiKeyRequest, token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return create_api_key(
        username=token_data.username,
        role=token_data.role,
        description=body.description
    )

@app.get("/apikeys")
async def list_keys(token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    return get_api_keys(token_data.username)

@app.delete("/apikeys/{key_id}")
async def delete_key(key_id: int, token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    success = delete_api_key(key_id, token_data.username)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"message": "API Key deleted"}

# ─── Query with API Key ────────────────────────────────
@app.post("/query/apikey")
async def query_with_apikey(request: Request, body: QueryRequest):
    ip = request.client.host

    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key required")

    user = verify_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    username = user["username"]
    role = user["role"]

    allowed, reason = check_rate_limit(username, ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)

    security = evaluate_threats(body.prompt, role)
    if not security["safe"]:
        primary = security["primary_threat"]
        log_blocked_request(username, role, primary["reason"], body.prompt, ip)
        log_security_event(
            event_type=primary["type"],
            username=username,
            role=role,
            details=f"Risk Score: {security['risk_score']}",
            severity="HIGH"
        )
        raise HTTPException(status_code=400, detail=f"Attack detected: {primary['type']}")

    log_request(username, role, "apikey_query", body.prompt, ip, "PROCESSING")
    result = query_rag(body.prompt, role)
    safety = check_response_safety(result["answer"], role)
    if not safety["is_safe"]:
        raise HTTPException(status_code=403, detail="Response blocked by DLP")

    log_request(username, role, "apikey_query", body.prompt, ip, "SUCCESS")

    return QueryResponse(
        answer=safety["cleaned_response"],
        sources=result.get("sources", []),
        role=role,
        status="success"
    )
