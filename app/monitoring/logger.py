import logging
import json
from datetime import datetime
from pathlib import Path

# الاحتفاظ بالـ file logging كـ backup
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "trustzai.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("TrustZAI")

def _save_to_db(event: dict, log_type: str = "REQUEST"):
    try:
        from app.database import save_log
        save_log(
            type=log_type,
            username=event.get("username", "unknown"),
            role=event.get("role", "unknown"),
            action=event.get("action", ""),
            status=event.get("status", ""),
            ip_address=event.get("ip_address", ""),
            details=json.dumps(event)
        )
    except Exception as e:
        logger.error(f"DB save error: {e}")

def log_request(username, role, action, prompt, ip_address, status):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "REQUEST",
        "username": username,
        "role": role,
        "action": action,
        "prompt_length": len(prompt),
        "ip_address": ip_address,
        "status": status
    }
    logger.info(json.dumps(event))
    _save_to_file(event)
    _save_to_db(event, "REQUEST")

def log_security_event(event_type, username, role, details, severity="HIGH"):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "SECURITY_EVENT",
        "event_type": event_type,
        "username": username,
        "role": role,
        "details": details,
        "severity": severity
    }
    if severity == "HIGH":
        logger.warning(json.dumps(event))
    else:
        logger.info(json.dumps(event))
    _save_to_file(event, "security_events.log")
    _save_to_db(event, "SECURITY_EVENT")

def log_blocked_request(username, role, reason, prompt, ip_address):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "BLOCKED",
        "username": username,
        "role": role,
        "reason": reason,
        "prompt_preview": prompt[:100],
        "ip_address": ip_address
    }
    logger.warning(json.dumps(event))
    _save_to_file(event, "blocked_requests.log")
    _save_to_db(event, "BLOCKED")

def _save_to_file(event: dict, filename: str = "trustzai.log"):
    filepath = LOG_DIR / filename
    with open(filepath, "a") as f:
        f.write(json.dumps(event) + "\n")
