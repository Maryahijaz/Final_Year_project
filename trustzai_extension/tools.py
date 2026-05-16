import httpx
from typing import Optional

TRUSTZAI_API = "http://192.168.10.10:8000"

class TrustZAIClient:
    def __init__(self):
        self.token = None
        self.role = None

    async def login(self, username: str, password: str) -> dict:
        """
        تسجيل الدخول والحصول على JWT token
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{TRUSTZAI_API}/login",
                data={
                    "username": username,
                    "password": password
                }
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.role = data["role"]
                return {
                    "success": True,
                    "role": self.role,
                    "message": f"Logged in as {username} ({self.role})"
                }
            return {
                "success": False,
                "message": f"Login failed: {response.text}"
            }

    async def query(self, prompt: str) -> dict:
        """
        إرسال سؤال للـ AI Agent
        """
        if not self.token:
            return {"error": "Not authenticated. Please login first."}

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{TRUSTZAI_API}/query",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"prompt": prompt}
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                return {"error": "🚨 Malicious prompt detected by TrustZAI"}
            elif response.status_code == 401:
                return {"error": "Session expired. Please login again."}
            elif response.status_code == 403:
                return {"error": "Access denied. Insufficient permissions."}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. Please wait."}
            else:
                return {"error": f"Error: {response.text}"}

    async def health_check(self) -> dict:
        """
        التحقق من حالة النظام
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{TRUSTZAI_API}/health")
            if response.status_code == 200:
                return response.json()
            return {"error": "System unavailable"}

# instance مشترك
client = TrustZAIClient()
