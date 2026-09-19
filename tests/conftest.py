"""Test configuration and shared fixtures for LiveSOC test suites."""
import os
import sys
import asyncio
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure backend path is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.main import app
from app.db.database import Base, get_db
from app.core.config import settings
from app.core.security import create_access_token

# Test in-memory SQLite database
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class MockRedisPubSub:
    """In-memory mock for Redis PubSub."""
    def __init__(self):
        self.channel = None
        self._queue = asyncio.Queue()

    async def subscribe(self, channel: str):
        self.channel = channel

    async def unsubscribe(self, channel: str):
        self.channel = None

    async def listen(self):
        while True:
            msg = await self._queue.get()
            yield msg


class MockRedis:
    """In-memory mock for aioredis client."""
    def __init__(self):
        self.published_messages = []
        self._pubsub = MockRedisPubSub()

    async def ping(self):
        return True

    async def aclose(self):
        pass

    async def publish(self, channel: str, message: str):
        self.published_messages.append({"channel": channel, "data": message})
        await self._pubsub._queue.put({"type": "message", "channel": channel, "data": message})
        return 1

    def pubsub(self):
        return self._pubsub


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated database session with tables recreated per test."""
    async with test_engine.begin() as conn:
        from app.models.alert import AlertDB  # ensure models registered
        await conn.run_sync(Base.metadata.create_all)

    async with TestingSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def mock_redis():
    """Mock Redis client instance."""
    fake_redis = MockRedis()
    with patch("redis.asyncio.from_url", return_value=fake_redis):
        yield fake_redis


@pytest_asyncio.fixture(scope="function")
async def mock_geoip():
    """Mock GeoIP threat intelligence enrichment to avoid external rate limits."""
    mock_data = {
        "country": "United States",
        "city": "San Jose",
        "lat": 37.3382,
        "lon": -121.8863,
        "latitude": 37.3382,
        "longitude": -121.8863,
        "threat_intel": {"provider": "mock-geoip", "risk_factor": "medium"},
    }
    with patch("app.services.parser.enrich_ip", new=AsyncMock(return_value=mock_data)):
        yield mock_data


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession, mock_redis, mock_geoip) -> AsyncGenerator[AsyncClient, None]:
    """Test HTTP client with overridden database session and mock external services."""
    async def override_get_db():
        async with TestingSessionLocal() as session:
            try:
                yield session
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db

    with patch("app.main.init_db", new=AsyncMock()):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def auth_token() -> str:
    """Generate a valid JWT token for regular test user."""
    return create_access_token({"sub": "user"})


@pytest.fixture
def auth_headers(auth_token: str) -> dict:
    """Authorization headers with valid Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def admin_headers(auth_token: str) -> dict:
    """Headers for admin operations (Bearer token + admin-key)."""
    return {
        "Authorization": f"Bearer {auth_token}",
        "admin-key": settings.ADMIN_API_KEY,
    }
