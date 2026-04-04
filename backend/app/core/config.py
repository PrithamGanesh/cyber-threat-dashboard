from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""
    
    # App
    APP_NAME: str = "LiveSOC"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Database (REQUIRED - no defaults)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://soc:changeme@postgres:5432/livesoc")

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379")
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
    REDIS_CHANNEL: str = "alerts"

    # CORS - parse from comma-separated string
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() 
        for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")
    ]

    # Threat Intel (optional - API keys won't be logged)
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # Scoring thresholds
    CRITICAL_SCORE: int = int(os.getenv("CRITICAL_SCORE", "80"))
    HIGH_SCORE: int = int(os.getenv("HIGH_SCORE", "60"))
    MEDIUM_SCORE: int = int(os.getenv("MEDIUM_SCORE", "40"))

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()