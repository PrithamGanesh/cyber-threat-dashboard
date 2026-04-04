# LiveSOC Security Hardening Guide

## Overview

This document outlines the security improvements implemented and additional recommendations for production deployment.

---

## ✅ Implemented Fixes

### 1. Environment Variable Configuration
**Fixed:** Hardcoded credentials in `docker-compose.yml` and `app/core/config.py`

**Changes:**
- ✅ Database credentials now loaded from environment variables
- ✅ CORS origins configurable via `ALLOWED_ORIGINS` env var
- ✅ Redis password support added
- ✅ API keys loaded securely without appearing in code
- ✅ Created `.env.example` for configuration template
- ✅ Created `.gitignore` to prevent .env commit

**Usage:**
```bash
# Copy template and edit with real values
cp .env.example .env
# Edit .env with your actual credentials
```

### 2. Database Connection Security
**Fixed:** Connection pool optimization and stale connection prevention

**Changes:**
- ✅ Added `pool_recycle=3600` to prevent stale PostgreSQL connections
- ✅ Added `start_period: 30s` to Docker health checks
- ✅ Pool pre-pinging enabled (`pool_pre_ping=True`)

### 3. Structured Logging
**Fixed:** Plain-text logging with potential credential exposure

**Changes:**
- ✅ Implemented JSON structured logging format
- ✅ Proper exception tracing and formatting
- ✅ All log output goes to stdout for container log aggregation
- ✅ Library noise suppressed (sqlalchemy, uvicorn)

### 4. API Error Handling
**Fixed:** Incomplete error handling in `/ingest` endpoint

**Changes:**
- ✅ Added comprehensive try-catch blocks with proper logging
- ✅ Validation of `source` parameter (suricata|zeek only)
- ✅ Proper HTTP error codes (400, 422, 500)
- ✅ Detailed error messages for debugging

### 5. Frontend Real-Time Streaming
**Fixed:** Missing reconnection logic for EventSource

**Changes:**
- ✅ Implemented exponential backoff retry mechanism
- ✅ Maximum 10 reconnection attempts with 30-second cap
- ✅ Proper cleanup of EventSource and timeouts
- ✅ Enhanced error logging and reporting

### 6. Performance Optimization
**Fixed:** N+1 query problem in stats endpoint

**Changes:**
- ✅ Consolidated 5 separate COUNT queries into single CASE-statement query
- ✅ Reduced database round-trips from 6 to 2
- ✅ Added proper type hints to all functions
- ✅ Comprehensive docstrings for all API endpoints

### 7. Threat Intelligence Enrichment
**Fixed:** Missing rate limiting documentation and error handling

**Changes:**
- ✅ Added comprehensive docstrings with rate limit warnings
- ✅ Timeout handling for external API calls
- ✅ User-Agent header added to requests
- ✅ IPv6 private range detection
- ✅ Graceful degradation when APIs are unavailable

---

## 🔴 Additional Security Recommendations for Production

### P0: CRITICAL - Must Implement Before Production

#### 1. HTTPS/TLS Configuration
**Current Status:** No HTTPS configured

**Required Action:**
```yaml
# docker-compose.yml - Add nginx TLS termination
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx-tls.conf:/etc/nginx/nginx.conf
      - ./certs/:/etc/nginx/certs/
    ports:
      - "443:443"
      - "80:80"
    depends_on:
      - backend
```

**Commands to generate certificates:**
```bash
# Self-signed (dev only)
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Production use Let's Encrypt via Certbot
```

#### 2. Database Secrets Management
**Current Status:** Env variables used, but stored in plaintext containers

**Fix Options:**
- **Docker Secrets** (Swarm): Store in `/run/secrets/` filesystem
- **HashiCorp Vault**: Centralized secrets management
- **AWS Secrets Manager**: Cloud-native solution
- **Kubernetes Secrets**: If using K8s

**Example with Docker Secrets:**
```yaml
secrets:
  db_password:
    file: ./secrets/db_password.txt
services:
  postgres:
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
```

#### 3. Redis Authentication
**Current Status:** No password required

**Fix:**
```conf
# streaming/redis.conf
requirepass your-strong-password-here
maxmemory 256mb
maxmemory-policy allkeys-lru
```

Backend config:
```python
REDIS_URL = f"redis://:{settings.REDIS_PASSWORD}@redis:6379"
```

#### 4. API Authentication & Authorization
**Current Status:** No authentication on endpoints

**Recommended:** Implement JWT or API keys
```python
# backend/app/api/auth.py (example)
from fastapi.security import HTTPBearer, HTTPAuthCredentials
import jwt

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

#### 5. Rate Limiting
**Current Status:** No rate limiting on endpoints

**Add package:**
```bash
pip install slowapi
```

**Implementation:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter

@app.get("/alerts", dependencies=[Depends(limiter.limit("100/minute"))])
async def list_alerts(...):
    ...
```

### P1: HIGH - Should Implement for Production

#### 6. Database Encryption at Rest
**Current Status:** Data stored in plaintext on disk

**Solutions:**
- PostgreSQL Transparent Data Encryption (TDE)
- Encrypted filesystem (LUKS, BitLocker)
- Cloud-managed encryption (AWS RDS with encryption)

#### 7. Audit Logging
**Current Status:** Basic application logging only

**Add:**
```python
# backend/app/core/audit_logger.py
import logging
from datetime import datetime

audit_logger = logging.getLogger("audit")

async def log_access(user: str, action: str, resource: str, status: int):
    """Log all significant actions for compliance."""
    audit_logger.info(
        f"AUDIT | time={datetime.utcnow().isoformat()} | user={user} | "
        f"action={action} | resource={resource} | status={status}"
    )
```

#### 8. Input Validation Hardening
**Current Status:** SQLAlchemy ORM prevents SQL injection, basic Pydantic validation

**Add:**
```python
# Stricter IP validation
from ipaddress import ipaddress

def validate_ip(ip_str: str) -> str:
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        raise ValueError(f"Invalid IP: {ip_str}")
```

#### 9. External API Rate Limiting
**Current Status:** In-memory cache with no rate limit tracking

**Add rate limiting for ip-api.com and AbuseIPDB:**
```python
# backend/app/services/rate_limiter.py
from datetime import datetime, timedelta
import asyncio

class APIRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests = []
    
    async def check_limit(self) -> bool:
        now = datetime.utcnow()
        self.requests = [t for t in self.requests if now - t < self.window]
        if len(self.requests) >= self.max_requests:
            return False
        self.requests.append(now)
        return True

# Usage
geo_limiter = APIRateLimiter(45, 60)  # 45/minute for ip-api.com
```

#### 10. Monitoring & Alerting
**Current Status:** No metrics exported

**Add:**
```bash
pip install prometheus-client
```

**Implementation:**
```python
from prometheus_client import Counter, Histogram, generate_latest

alert_count = Counter('alerts_total', 'Total alerts ingested', ['source'])
ingest_duration = Histogram('ingest_seconds', 'Alert ingestion duration')

@ingest_duration.time()
async def ingest_log(...):
    alert_count.labels(source=source).inc()
    ...

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

---

## 🛡️ Security Checklist for Deployment

### Before Going to Production
- [ ] HTTPS/TLS configured with valid certificates
- [ ] Database passwords stored in secrets manager (not plaintext)
- [ ] Redis requiring authentication (`requirepass`)
- [ ] API authentication/authorization implemented
- [ ] Rate limiting enabled on all endpoints
- [ ] Input validation comprehensive (IP addresses, URLs, etc.)
- [ ] Secrets not committed to git (verify `.gitignore`)
- [ ] Security headers added to responses:
  ```python
  app.add_middleware(
      TrustedHostMiddleware, 
      allowed_hosts=["yourdomain.com"]
  )
  ```
- [ ] CORS limited to specific trusted origins
- [ ] Logging configured with audit trail
- [ ] Database backups configured
- [ ] Monitoring and alerting set up
- [ ] Security scanning (bandit, safety) integrated into CI/CD
- [ ] Dependencies scanned for vulnerabilities (pip-audit)

### Security Testing
```bash
# Python code security scanning
pip install bandit
bandit -r backend/

# Dependency vulnerability check
pip install safety
safety check

# OWASP dependency check
# Download from https://jeremylong.github.io/DependencyCheck/
```

### CI/CD Integration
```yaml
# .github/workflows/security.yml (example)
name: Security Checks
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Bandit
        run: pip install bandit && bandit -r backend/
      - name: Check Dependencies
        run: pip install safety && safety check
```

---

## 🔐 Environment Variable Template

Create `.env` with:
```ini
# Database (CHANGE THESE!)
DATABASE_URL=postgresql+asyncpg://soc:STRONG_PASSWORD@postgres:5432/livesoc
DB_USER=soc
DB_PASSWORD=STRONG_PASSWORD

# Redis
REDIS_URL=redis://:REDIS_PASSWORD@redis:6379
REDIS_PASSWORD=STRONG_REDIS_PASSWORD

# API Security
DEBUG=false
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
SECRET_KEY=your-secret-key-for-jwt-tokens

# Threat Intel
ABUSEIPDB_API_KEY=your-api-key
VIRUSTOTAL_API_KEY=your-api-key

# Scoring
CRITICAL_SCORE=80
HIGH_SCORE=60
MEDIUM_SCORE=40
```

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/sql-syntax.html)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

---

## Support

For security incidents, follow responsible disclosure:
1. Do NOT open public issues for security vulnerabilities
2. Email: security@yourdomain.com
3. Allow 90 days for patch before public disclosure
