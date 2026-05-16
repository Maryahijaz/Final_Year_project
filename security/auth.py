from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# مفتاح مختلف تماماً عن TrustZAI
SECRET_KEY = "monitoring-secret-key-2025-independent"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# مستخدمون خاصون بالـ Monitoring فقط
USERS_DB = {
    "monitor_admin": {
        "username": "monitor_admin",
        "password": pwd_context.hash("Monitor@2025"),
        "role": "admin"
    },
    "monitor_analyst": {
        "username": "monitor_analyst",
        "password": pwd_context.hash("Analyst@2025"),
        "role": "analyst"
    }
}

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def authenticate_user(username: str, password: str):
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["password"]):
        return None
    return user

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if not username:
            return None
        return TokenData(username=username, role=role)
    except JWTError:
        return None
