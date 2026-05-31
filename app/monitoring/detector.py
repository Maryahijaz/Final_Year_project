from datetime import datetime, timedelta
from collections import defaultdict
from app.monitoring.logger import log_security_event

# تتبع الطلبات لكل مستخدم
request_tracker = defaultdict(list)
failed_login_tracker = defaultdict(list)

# إعدادات الحدود
RATE_LIMIT_REQUESTS = 20      # حد الطلبات
RATE_LIMIT_WINDOW = 60        # ثانية
MAX_FAILED_LOGINS = 5         # محاولات فاشلة
FAILED_LOGIN_WINDOW = 300     # 5 دقائق

def check_rate_limit(username: str, ip_address: str) -> tuple:
    """
    يتحقق من عدد الطلبات في الوقت المحدد
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)

    # تنظيف الطلبات القديمة
    request_tracker[username] = [
        t for t in request_tracker[username]
        if t > window_start
    ]

    # إضافة الطلب الحالي
    request_tracker[username].append(now)

    count = len(request_tracker[username])

    if count > RATE_LIMIT_REQUESTS:
        log_security_event(
            event_type="RATE_LIMIT_EXCEEDED",
            username=username,
            role="unknown",
            details=f"IP: {ip_address} — {count} requests in {RATE_LIMIT_WINDOW}s",
            severity="HIGH"
        )
        return False, f"Rate limit exceeded: {count} requests in {RATE_LIMIT_WINDOW}s"

    return True, ""

def track_failed_login(username: str, ip_address: str) -> tuple:
    """
    يتتبع محاولات الدخول الفاشلة
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=FAILED_LOGIN_WINDOW)

    failed_login_tracker[username] = [
        t for t in failed_login_tracker[username]
        if t > window_start
    ]

    failed_login_tracker[username].append(now)
    count = len(failed_login_tracker[username])

    if count >= MAX_FAILED_LOGINS:
        log_security_event(
            event_type="BRUTE_FORCE_DETECTED",
            username=username,
            role="unknown",
            details=f"IP: {ip_address} — {count} failed logins in {FAILED_LOGIN_WINDOW}s",
            severity="HIGH"
        )
        return False, f"Account locked: too many failed attempts"

    return True, ""

def is_account_locked(username: str) -> bool:
    """
    يتحقق إذا كان الحساب مقفلاً
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=FAILED_LOGIN_WINDOW)

    recent_failures = [
        t for t in failed_login_tracker[username]
        if t > window_start
    ]

    return len(recent_failures) >= MAX_FAILED_LOGINS

def detect_suspicious_pattern(
    username: str,
    role: str,
    prompts: list
) -> tuple:
    """
    يكشف أنماط مشبوهة في تسلسل الطلبات
    """
    if len(prompts) < 3:
        return False, ""

    # كشف محاولات enumeration
    cve_count = sum(1 for p in prompts if "CVE-" in p.upper())
    if cve_count > 10:
        log_security_event(
            event_type="ENUMERATION_DETECTED",
            username=username,
            role=role,
            details=f"Excessive CVE queries: {cve_count}",
            severity="MEDIUM"
        )
        return True, "Suspicious enumeration pattern detected"

    return False, ""
