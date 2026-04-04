from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, AsyncGenerator, Dict, Any
import asyncio
import json
import redis.asyncio as aioredis
import logging

from app.db.database import get_db
from app.db import crud
from app.models.alert import AlertResponse, AlertCreate, AlertStats
from app.services.parser import parse_log_line
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    source_ip: Optional[str] = None,
    alert_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> List[AlertResponse]:
    """Retrieve paginated alerts with optional filters.
    
    Args:
        skip: Number of alerts to skip (pagination offset)
        limit: Number of alerts to return (1-500)
        severity: Filter by severity (critical|high|medium|low)
        source_ip: Filter by source IP address
        alert_type: Filter by alert type/signature
        db: Database session
    
    Returns:
        List of alerts matching the filters
    """
    try:
        alerts = await crud.get_alerts(
            db, 
            skip=skip, 
            limit=limit, 
            severity=severity,
            source_ip=source_ip, 
            alert_type=alert_type
        )
        return alerts
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@router.get("/stats", response_model=AlertStats)
async def alert_stats(db: AsyncSession = Depends(get_db)) -> AlertStats:
    """Aggregate alert statistics (total, by severity, unique sources).
    
    Returns:
        AlertStats with counts and top categories
    """
    try:
        stats = await crud.get_alert_stats(db)
        return stats
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.get("/stream")
async def stream_alerts() -> StreamingResponse:
    """Server-Sent Events endpoint for real-time alert streaming.
    
    Subscribes to Redis pub/sub channel and streams new alerts to the browser.
    
    Returns:
        StreamingResponse with text/event-stream media type
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        """Generate alert events from Redis pub/sub channel."""
        redis = None
        try:
            redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = redis.pubsub()
            await pubsub.subscribe(settings.REDIS_CHANNEL)
            
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield f"data: {message['data']}\n\n"
        except asyncio.CancelledError:
            logger.debug("SSE stream cancelled by client")
        except Exception as e:
            logger.warning(f"SSE stream error: {e}")
        finally:
            if redis:
                try:
                    await pubsub.unsubscribe(settings.REDIS_CHANNEL)
                    await redis.aclose()
                except Exception as e:
                    logger.debug(f"Error closing Redis connection: {e}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/ingest", response_model=AlertResponse, status_code=201)
async def ingest_log(
    payload: Dict[str, Any],
    background_tasks: BackgroundTasks,
    source: str = Query("suricata", description="Log source: suricata or zeek"),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    """Ingest a raw log line from IDS system.
    
    Parses, scores, geo-enriches, persists, and publishes to Redis.
    
    Args:
        payload: Raw log entry as JSON dict
        background_tasks: Background task runner for async operations
        source: Log source type (suricata or zeek)
        db: Database session
    
    Returns:
        Created alert response
    
    Raises:
        HTTPException 422: If log entry does not produce an alert
        HTTPException 500: If database or parsing error occurs
    """
    try:
        # Validate source parameter
        if source not in ["suricata", "zeek"]:
            raise HTTPException(
                status_code=400, 
                detail="Source must be 'suricata' or 'zeek'"
            )
        
        # Parse the log entry
        raw_line = json.dumps(payload)
        alert = await parse_log_line(raw_line, source=source)
        
        if not alert:
            logger.warning(f"Log entry did not produce an alert: {source}")
            raise HTTPException(
                status_code=422, 
                detail="Log entry did not produce an alert (check event type and filter rules)"
            )

        # Persist to database
        db_alert = await crud.create_alert(db, alert)
        logger.info(f"Created alert {db_alert.id} from {source}")

        # Publish to Redis async (fire-and-forget)
        background_tasks.add_task(_publish_alert, db_alert)

        return db_alert
    
    except HTTPException:
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        logger.error(f"Error ingesting log: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to ingest log entry")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int, 
    db: AsyncSession = Depends(get_db)
) -> AlertResponse:
    """Retrieve a single alert by ID.
    
    Args:
        alert_id: Alert ID
        db: Database session
    
    Returns:
        Alert response
    
    Raises:
        HTTPException 404: If alert not found
    """
    try:
        alert = await crud.get_alert_by_id(db, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert")


@router.delete("/reset", status_code=204)
async def reset_alerts(db: AsyncSession = Depends(get_db)) -> None:
    """Clear all alerts from database (useful for demo resets).
    
    WARNING: This permanently deletes all alerts!
    
    Args:
        db: Database session
    """
    try:
        await crud.delete_all_alerts(db)
        logger.warning("All alerts have been deleted")
    except Exception as e:
        logger.error(f"Error resetting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset alerts")


async def _publish_alert(alert: Any) -> None:
    """Publish a serialized alert to Redis for SSE consumers.
    
    This runs as a background task and doesn't block the API response.
    Failures are logged but don't fail the request.
    
    Args:
        alert: AlertDB instance to publish
    """
    redis = None
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        payload = AlertResponse.model_validate(alert).model_dump_json()
        await redis.publish(settings.REDIS_CHANNEL, payload)
        logger.debug(f"Published alert {alert.id} to Redis")
    except Exception as e:
        logger.warning(f"Redis publish failed for alert {alert.id}: {e}")
    finally:
        if redis:
            try:
                await redis.aclose()
            except Exception as e:
                logger.debug(f"Error closing Redis connection: {e}")