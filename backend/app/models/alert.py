from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text
from sqlalchemy.sql import func
from app.db.database import Base
from pydantic import BaseModel, ConfigDict, field_validator, constr
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum
import ipaddress


class SeverityEnum(str, Enum):
    """Allowed severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertSourceEnum(str, Enum):
    """Allowed alert sources."""
    SURICATA = "suricata"
    ZEEK = "zeek"


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
    alert_type: constr(max_length=100)
    severity: SeverityEnum
    score: float = 0.0
    signature: Optional[constr(max_length=255)] = None
    category: Optional[constr(max_length=100)] = None
    country: Optional[constr(max_length=100)] = None
    city: Optional[constr(max_length=100)] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    raw_log: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    source: AlertSourceEnum = AlertSourceEnum.SURICATA

    @field_validator("source_ip", "dest_ip", mode="before")
    @classmethod
    def validate_ip_address(cls, v):
        """Validate that source_ip and dest_ip are valid IP addresses."""
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")

    @field_validator("source_port", "dest_port", mode="before")
    @classmethod
    def validate_port(cls, v):
        """Validate port numbers (1-65535)."""
        if v is None:
            return v
        if not isinstance(v, int) or v < 1 or v > 65535:
            raise ValueError(f"Invalid port number: {v}. Must be between 1-65535")
        return v

    @field_validator("score", mode="before")
    @classmethod
    def validate_score(cls, v):
        """Validate score is between 0 and 100."""
        if not isinstance(v, (int, float)):
            raise ValueError("Score must be a number")
        if v < 0 or v > 100:
            raise ValueError(f"Score must be between 0-100, got {v}")
        return v

    @field_validator("latitude", "longitude", mode="before")
    @classmethod
    def validate_coordinates(cls, v):
        """Validate latitude and longitude ranges."""
        if v is None:
            return v
        if not isinstance(v, (int, float)):
            raise ValueError("Coordinates must be numbers")
        return v


class AlertCreate(AlertBase):
    pass


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class AlertStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unique_sources: int
    top_categories: list
