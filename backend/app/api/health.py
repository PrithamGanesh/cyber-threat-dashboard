from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as aioredis
import logging

from app.db.database import get_db
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/")
async def health_check(db: AsyncSession = Depends(get_db)):
    status = {"api": "ok", "database": "unknown", "redis": "unknown"}

    try:
        await db.execute(text("SELECT 1"))
        status["database"] = "ok"
    except Exception as e:
        status["database"] = f"error: {e}"

    try:
        redis = aioredis.from_url(settings.REDIS_URL)
        await redis.ping()
        await redis.aclose()
        status["redis"] = "ok"
    except Exception as e:
        status["redis"] = f"error: {e}"

    overall = "healthy" if all(v == "ok" for v in status.values()) else "degraded"
    return {"status": overall, "services": status}