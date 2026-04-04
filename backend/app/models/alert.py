from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text
from sqlalchemy.sql import func
from app.db.database import Base
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


# SQLAlchemy ORM Model
class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source_ip = Column(String(45), index=True)
    dest_ip = Column(String(45), index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    alert_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)  # critical / high / medium / low
    score = Column(Float, default=0.0)
    signature = Column(String(255), nullable=True)
    category = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    raw_log = Column(JSON, nullable=True)
    threat_intel = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    source = Column(String(50), default="suricata")  # suricata / zeek


# Pydantic Schemas
class AlertBase(BaseModel):
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    alert_type: str
    severity: str
    score: float = 0.0
    signature: Optional[str] = None
    category: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    raw_log: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    source: str = "suricata"


class AlertCreate(AlertBase):
    pass


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


class AlertStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unique_sources: int
    top_categories: list