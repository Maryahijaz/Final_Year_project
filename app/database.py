from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy import text

# إعدادات الاتصال
DATABASE_URL = "postgresql://trustzai:TrustZAI%402025@192.168.20.10:5432/trustzai_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─── Models ───────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class SecurityLog(Base):
    __tablename__ = "security_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    type = Column(String(50))
    username = Column(String(50))
    role = Column(String(20))
    action = Column(String(100))
    status = Column(String(50))
    ip_address = Column(String(50))
    details = Column(Text)

class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    username = Column(String(50))
    token_hash = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)

# ─── DB Functions ──────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(username: str):
    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()

def save_log(type: str, username: str, role: str, action: str,
             status: str, ip_address: str, details: str = ""):
    db = SessionLocal()
    try:
        log = SecurityLog(
            type=type,
            username=username,
            role=role,
            action=action,
            status=status,
            ip_address=ip_address,
            details=details
        )
        db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"DB Log Error: {e}")
    finally:
        db.close()

def get_logs(limit: int = 100):
    db = SessionLocal()
    try:
        logs = db.query(SecurityLog).order_by(
            SecurityLog.timestamp.desc()
        ).limit(limit).all()
        return [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "type": l.type,
                "username": l.username,
                "role": l.role,
                "action": l.action,
                "status": l.status,
                "ip_address": l.ip_address,
                "details": l.details
            }
            for l in logs
        ]
    finally:
        db.close()

def test_connection():
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        print(f"DB Connection Error: {e}")
        return False

