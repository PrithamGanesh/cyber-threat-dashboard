from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, distinct, case
from app.models.alert import AlertDB, AlertCreate, AlertStats
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


async def create_alert(db: AsyncSession, alert: AlertCreate) -> AlertDB:
    """Create and persist a new alert to the database."""
    db_alert = AlertDB(**alert.model_dump())
    db.add(db_alert)
    await db.commit()
    await db.refresh(db_alert)
    return db_alert


async def get_alerts(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> List[AlertDB]:
    """Retrieve paginated alerts with optional filtering."""
    query = select(AlertDB).order_by(desc(AlertDB.timestamp))

    if severity:
        query = query.where(AlertDB.severity == severity)
    if source_ip:
        query = query.where(AlertDB.source_ip == source_ip)
    if alert_type:
        query = query.where(AlertDB.alert_type == alert_type)

    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


async def get_alert_by_id(db: AsyncSession, alert_id: int) -> Optional[AlertDB]:
    """Retrieve a single alert by ID."""
    result = await db.execute(select(AlertDB).where(AlertDB.id == alert_id))
    return result.scalar_one_or_none()


async def get_alert_stats(db: AsyncSession) -> AlertStats:
    """Aggregate alert statistics using a single optimized query (no N+1)."""
    # Single query using CASE statements to avoid multiple queries
    stats_query = select(
        func.count(AlertDB.id).label("total"),
        func.sum(case((AlertDB.severity == "critical", 1), else_=0)).label("critical"),
        func.sum(case((AlertDB.severity == "high", 1), else_=0)).label("high"),
        func.sum(case((AlertDB.severity == "medium", 1), else_=0)).label("medium"),
        func.sum(case((AlertDB.severity == "low", 1), else_=0)).label("low"),
        func.count(distinct(AlertDB.source_ip)).label("unique_sources"),
    )
    
    stats_result = await db.execute(stats_query)
    row = stats_result.first()
    
    total, critical, high, medium, low, unique_sources = row if row else (0, 0, 0, 0, 0, 0)

    # Top 5 categories (separate query, acceptable for low-frequency operation)
    cat_result = await db.execute(
        select(AlertDB.category, func.count(AlertDB.id).label("count"))
        .group_by(AlertDB.category)
        .order_by(desc("count"))
        .limit(5)
    )
    top_categories = [{"category": row[0], "count": row[1]} for row in cat_result.fetchall()]

    return AlertStats(
        total=total or 0,
        critical=critical or 0,
        high=high or 0,
        medium=medium or 0,
        low=low or 0,
        unique_sources=unique_sources or 0,
        top_categories=top_categories,
    )


async def delete_all_alerts(db: AsyncSession) -> None:
    """Delete all alerts from the database (useful for demo resets)."""
    await db.execute(AlertDB.__table__.delete())
    await db.commit()