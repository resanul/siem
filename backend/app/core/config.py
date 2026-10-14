"""
OpenSOC Forge - Application Configuration & Settings.
"""

import os
from pydantic import BaseModel


class Settings(BaseModel):
    PROJECT_NAME: str = "OpenSOC Forge"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("OPENSOC_SECRET_KEY", "opensoc-forge-super-secret-key-change-in-prod-32bytes")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ALGORITHM: str = "HS256"
    DEMO_MODE: bool = True  # Development mode clearly labeled with demo telemetry


settings = Settings()
