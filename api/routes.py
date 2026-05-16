from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.auth import authenticate_user, create_token, verify_token, TOKEN_EXPIRE_MINUTES
from security.rbac import check_permission
from security.guard import analyze_prompt
from log_reader import read_logs, get_stats
from analyzer import analyze

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class QueryRequest(BaseModel):
    question: str

# ─── Login ────────────────────────────────────
@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }

# ─── Stats ────────────────────────────────────
@router.get("/stats")
async def stats(token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not check_permission(token_data.role, "view_logs"):
        raise HTTPException(status_code=403, detail="Permission denied")
    return get_stats()

# ─── Logs ─────────────────────────────────────
@router.get("/logs/{log_type}")
async def logs(log_type: str, token: str = Depends(oauth2_scheme)):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not check_permission(token_data.role, "view_logs"):
        raise HTTPException(status_code=403, detail="Permission denied")
    return read_logs(log_type, 50)

# ─── Analyze ──────────────────────────────────
@router.post("/analyze")
async def analyze_logs(
    body: QueryRequest,
    token: str = Depends(oauth2_scheme)
):
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid token")

    role = token_data.role

    if not check_permission(role, "analyze_logs"):
        raise HTTPException(status_code=403, detail="Permission denied")

    # Prompt Security Check
    result = analyze_prompt(body.question, role)
    if not result["safe"]:
        raise HTTPException(status_code=400, detail=f"Blocked: {result['reason']}")

    # Analyze with Mistral
    answer = analyze(result["sanitized"])

    return {
        "answer": answer,
        "role": role,
        "status": "success"
    }

# ─── Health ───────────────────────────────────
@router.get("/health")
async def health():
    return {
        "status": "running",
        "service": "TrustZAI Monitoring",
        "model": "mistral",
        "version": "1.0.0"
    }
