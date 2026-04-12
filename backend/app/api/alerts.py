from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, AsyncGenerator, Dict, Any
import asyncio
import json
import redis.asyncio as aioredis
import logging
import ipaddress

from app.db.database import get_db
from app.db import crud
from app.models.alert import AlertResponse, AlertCreate, AlertStats, SeverityEnum, AlertSourceEnum
from app.services.parser import parse_log_line
from app.core.config import settings
from app.core.security import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[SeverityEnum] = Query(None),
    source_ip: Optional[str] = None,
    alert_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> List[AlertResponse]:
    """Retrieve paginated alerts with optional filters.
    
    Requires: Bearer token authentication
    
    Args:
        skip: Number of alerts to skip (pagination offset)
        limit: Number of alerts to return (1-500)
        severity: Filter by severity (critical|high|medium|low)
        source_ip: Filter by source IP address (must be valid IP)
        alert_type: Filter by alert type/signature
        db: Database session
        current_user: Authenticated user (from JWT token)
    
    Returns:
        List of alerts matching the filters
    """
    # Validate source_ip if provided
    if source_ip:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {source_ip}")
    
    try:
        alerts = await crud.get_alerts(
            db, 
            skip=skip, 
            limit=limit, 
            severity=severity.value if severity else None,
            source_ip=source_ip, 
            alert_type=alert_type
        )
        return alerts
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AlertStats:
    """Aggregate alert statistics (total, by severity, unique sources).
    
    Requires: Bearer token authentication
    
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
async def stream_alerts(
    current_user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Server-Sent Events endpoint for real-time alert streaming.
    
    Requires: Bearer token authentication
    
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
    source: AlertSourceEnum = Query(AlertSourceEnum.SURICATA, description="Log source: suricata or zeek"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AlertResponse:
    """Ingest a raw log line from IDS system.
    
    Requires: Bearer token authentication
    
    Parses, scores, geo-enriches, persists, and publishes to Redis.
    
    Args:
        payload: Raw log entry as JSON dict
        background_tasks: Background task runner for async operations
        source: Log source type (suricata or zeek)
        db: Database session
        current_user: Authenticated user (from JWT token)
    
    Returns:
        Created alert response
    
    Raises:
        HTTPException 422: If log entry does not produce an alert
        HTTPException 500: If database or parsing error occurs
    """
    try:
        # Parse the log entry
        raw_line = json.dumps(payload)
        alert = await parse_log_line(raw_line, source=source.value)
        
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
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AlertResponse:
    """Retrieve a single alert by ID.
    
    Requires: Bearer token authentication
    
    Args:
        alert_id: Alert ID
        db: Database session
        current_user: Authenticated user (from JWT token)
    
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
async def reset_alerts(
    admin_key: str = Header(None),
    db: AsyncSession = Depends(get_db)
) -> None:
    """Clear all alerts from database (useful for demo resets).
    
    WARNING: This permanently deletes all alerts!
    
    Requires: admin-key header with correct admin API key
    
    Args:
        admin_key: Admin API key from header
        db: Database session
    
    Raises:
        HTTPException 401: If admin key is missing or invalid
    """
    # Validate admin API key
    if not admin_key or admin_key != settings.ADMIN_API_KEY:
        logger.warning(f"Unauthorized reset attempt with key: {admin_key}")
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid or missing admin-key header"
        )
    
    try:
        await crud.delete_all_alerts(db)
        logger.warning("All alerts have been deleted by admin")
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