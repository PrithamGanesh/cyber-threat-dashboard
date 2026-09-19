"""Regression Test Suite for LiveSOC.

Verifies system components against regressions in:
- Authentication & JWT token validation
- IDS log parsing (Suricata & Zeek)
- Scoring heuristics and boundary clamping
- Threat intelligence IP classification and validation
- Database CRUD queries, filters, and single-query statistics
- API input validation and HTTP error contracts
"""
import pytest
from datetime import timedelta
import json
from pydantic import ValidationError

from app.core.security import create_access_token, verify_token
from app.services.parser import parse_suricata_eve, parse_zeek_conn, parse_log_line
from app.services.scoring import calculate_score
from app.services.threat_intel import _is_private_ip
from app.models.alert import AlertCreate, AlertDB, SeverityEnum, AlertSourceEnum
from app.db import crud


# ============================================================================
# 1. Authentication & Security Regressions
# ============================================================================

@pytest.mark.asyncio
async def test_auth_login_valid_credentials(client):
    """Ensure valid credentials issue a valid JWT Bearer token."""
    response = await client.post("/api/v1/auth/login", json={"username": "user", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    
    # Verify token payload
    payload = verify_token(data["access_token"])
    assert payload["sub"] == "user"


@pytest.mark.asyncio
async def test_auth_login_invalid_password(client):
    """Ensure incorrect password returns 401 Unauthorized."""
    response = await client.post("/api/v1/auth/login", json={"username": "user", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_login_nonexistent_user(client):
    """Ensure non-existent user returns 401 Unauthorized."""
    response = await client.post("/api/v1/auth/login", json={"username": "hacker", "password": "password123"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_unauthenticated(client):
    """Ensure unauthenticated access to /api/v1/alerts/ is blocked."""
    response = await client.get("/api/v1/alerts/")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_expired_token(client):
    """Ensure expired JWT tokens are rejected."""
    expired_token = create_access_token({"sub": "user"}, expires_delta=timedelta(seconds=-10))
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = await client.get("/api/v1/alerts/", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_tampered_token(client):
    """Ensure tampered tokens fail verification."""
    valid_token = create_access_token({"sub": "user"})
    tampered_token = valid_token[:-4] + "fake"
    headers = {"Authorization": f"Bearer {tampered_token}"}
    response = await client.get("/api/v1/alerts/", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_reset_endpoint_security_guard(client, auth_headers):
    """Ensure /api/v1/alerts/reset strictly enforces admin-key validation."""
    # Missing admin key
    resp_missing = await client.delete("/api/v1/alerts/reset", headers=auth_headers)
    assert resp_missing.status_code == 401
    
    # Invalid admin key
    bad_headers = {**auth_headers, "admin-key": "wrong-secret-key"}
    resp_bad = await client.delete("/api/v1/alerts/reset", headers=bad_headers)
    assert resp_bad.status_code == 401


# ============================================================================
# 2. Log Parsing Engine Regressions
# ============================================================================

def test_parse_suricata_eve_valid_alert():
    """Ensure Suricata alert events are correctly mapped to AlertCreate."""
    raw = {
        "event_type": "alert",
        "src_ip": "198.51.100.15",
        "dest_ip": "192.168.1.50",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "tcp",
        "alert": {
            "signature": "ET EXPLOIT Apache Struts RCE",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        }
    }
    alert = parse_suricata_eve(raw)
    assert alert is not None
    assert alert.source_ip == "198.51.100.15"
    assert alert.dest_ip == "192.168.1.50"
    assert alert.severity == SeverityEnum.CRITICAL
    assert alert.alert_type == "ET EXPLOIT Apache Struts RCE"
    assert alert.source == AlertSourceEnum.SURICATA
    assert alert.score > 70


def test_parse_suricata_eve_ignores_non_alerts():
    """Ensure non-alert Suricata events (flow, dns, stats) return None."""
    raw_dns = {
        "event_type": "dns",
        "src_ip": "192.168.1.100",
        "dest_ip": "8.8.8.8",
        "dns": {"type": "query", "rrname": "example.com"}
    }
    assert parse_suricata_eve(raw_dns) is None


def test_parse_zeek_conn_suspicious_port():
    """Ensure Zeek connections on suspicious ports (e.g. 4444) trigger alerts."""
    raw = {
        "id.orig_h": "203.0.113.5",
        "id.resp_h": "192.168.1.10",
        "id.orig_p": 49152,
        "id.resp_p": 4444,
        "proto": "tcp",
        "duration": 5.2,
        "orig_bytes": 1200,
    }
    alert = parse_zeek_conn(raw)
    assert alert is not None
    assert alert.source_ip == "203.0.113.5"
    assert alert.dest_port == 4444
    assert alert.severity == SeverityEnum.HIGH
    assert alert.source == AlertSourceEnum.ZEEK


def test_parse_zeek_conn_high_data_transfer_alert():
    """Ensure long duration and massive byte transfers trigger suspicious connection alert."""
    raw = {
        "id.orig_h": "198.51.100.8",
        "id.resp_h": "192.168.1.20",
        "id.orig_p": 50123,
        "id.resp_p": 8080,
        "proto": "tcp",
        "duration": 4000,
        "orig_bytes": 5_000_000,
    }
    alert = parse_zeek_conn(raw)
    assert alert is not None
    assert alert.severity == SeverityEnum.MEDIUM


def test_parse_zeek_conn_ignores_normal_traffic():
    """Ensure standard web traffic is not incorrectly flagged as an alert."""
    raw = {
        "id.orig_h": "192.168.1.100",
        "id.resp_h": "93.184.216.34",
        "id.orig_p": 55123,
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.5,
        "orig_bytes": 3500,
    }
    assert parse_zeek_conn(raw) is None


@pytest.mark.asyncio
async def test_parse_log_line_graceful_malformed_json():
    """Ensure malformed JSON input returns None instead of raising exceptions."""
    result = await parse_log_line("INVALID_RAW_STRING", source="suricata")
    assert result is None


# ============================================================================
# 3. Scoring Engine Regressions
# ============================================================================

def test_scoring_monotonicity_across_severities():
    """Ensure critical > high > medium > low under identical category and IP."""
    s_crit = calculate_score("critical", "Web Application Attack", "203.0.113.1")
    s_high = calculate_score("high", "Web Application Attack", "203.0.113.1")
    s_med = calculate_score("medium", "Web Application Attack", "203.0.113.1")
    s_low = calculate_score("low", "Web Application Attack", "203.0.113.1")
    
    assert s_crit > s_high > s_med > s_low


def test_scoring_category_bonuses():
    """Ensure malicious categories (malware, exploit, trojan) amplify score."""
    base_score = calculate_score("medium", "Generic Traffic", "203.0.113.1")
    exploit_score = calculate_score("medium", "Attempted Exploit Execution", "203.0.113.1")
    trojan_score = calculate_score("medium", "Trojan Activity Detected", "203.0.113.1")

    assert exploit_score > base_score
    assert trojan_score > base_score


def test_scoring_private_ip_score_damping():
    """Ensure internal private IPs are scored lower than external threats."""
    public_score = calculate_score("high", "Port Scan", "198.51.100.99")
    private_score = calculate_score("high", "Port Scan", "192.168.1.100")
    
    assert private_score < public_score


def test_scoring_boundary_clamping():
    """Ensure scores are strictly clamped between [0.0, 100.0]."""
    max_score = calculate_score("critical", "Trojan Malware Exploit Rootkit", "203.0.113.1")
    min_score = calculate_score("low", "", "10.0.0.1")
    
    assert 0.0 <= min_score <= 100.0
    assert 0.0 <= max_score <= 100.0


# ============================================================================
# 4. Threat Intel & IP Validation Regressions
# ============================================================================

def test_threat_intel_private_and_loopback_classification():
    """Ensure private RFC 1918 and loopback IPs are correctly classified."""
    assert _is_private_ip("127.0.0.1") is True
    assert _is_private_ip("10.0.0.5") is True
    assert _is_private_ip("172.16.1.1") is True
    assert _is_private_ip("192.168.1.100") is True
    assert _is_private_ip("::1") is True
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("203.0.113.45") is False


def test_alert_model_rejects_invalid_ip():
    """Ensure Pydantic schema validation rejects invalid IP addresses."""
    with pytest.raises(ValidationError):
        AlertCreate(
            source_ip="999.999.999.999",
            dest_ip="192.168.1.1",
            alert_type="Test Alert",
            severity=SeverityEnum.HIGH,
        )


def test_alert_model_rejects_invalid_ports():
    """Ensure port numbers outside 1-65535 raise ValidationError."""
    with pytest.raises(ValidationError):
        AlertCreate(
            source_ip="192.168.1.5",
            dest_ip="192.168.1.1",
            source_port=70000,
            alert_type="Port Test",
            severity=SeverityEnum.LOW,
        )


def test_alert_model_rejects_out_of_bounds_score():
    """Ensure scores > 100 or < 0 raise ValidationError."""
    with pytest.raises(ValidationError):
        AlertCreate(
            source_ip="192.168.1.5",
            dest_ip="192.168.1.1",
            alert_type="Score Test",
            severity=SeverityEnum.LOW,
            score=150.0,
        )


# ============================================================================
# 5. Database CRUD & Single-Query Statistics Regressions
# ============================================================================

@pytest.mark.asyncio
async def test_crud_create_get_and_filter_alerts(db_session):
    """Ensure alerts can be persisted, paginated, and filtered by severity and IP."""
    alert1 = AlertCreate(
        source_ip="198.51.100.1",
        dest_ip="10.0.0.1",
        alert_type="Brute Force",
        severity=SeverityEnum.CRITICAL,
        score=95.0,
        category="Authentication",
    )
    alert2 = AlertCreate(
        source_ip="198.51.100.2",
        dest_ip="10.0.0.2",
        alert_type="Port Scan",
        severity=SeverityEnum.LOW,
        score=20.0,
        category="Reconnaissance",
    )
    
    await crud.create_alert(db_session, alert1)
    await crud.create_alert(db_session, alert2)
    
    # List all
    all_alerts = await crud.get_alerts(db_session)
    assert len(all_alerts) == 2
    
    # Filter by severity
    crit_alerts = await crud.get_alerts(db_session, severity="critical")
    assert len(crit_alerts) == 1
    assert crit_alerts[0].alert_type == "Brute Force"
    
    # Filter by source IP
    ip_alerts = await crud.get_alerts(db_session, source_ip="198.51.100.2")
    assert len(ip_alerts) == 1
    assert ip_alerts[0].severity == "low"


@pytest.mark.asyncio
async def test_crud_stats_aggregation_accuracy(db_session):
    """Ensure get_alert_stats computes counts and top categories accurately in single query."""
    severities = [
        SeverityEnum.CRITICAL,
        SeverityEnum.CRITICAL,
        SeverityEnum.HIGH,
        SeverityEnum.MEDIUM,
        SeverityEnum.LOW,
    ]
    for i, sev in enumerate(severities):
        await crud.create_alert(
            db_session,
            AlertCreate(
                source_ip=f"203.0.113.{i+1}",
                dest_ip="192.168.1.1",
                alert_type=f"Alert {i}",
                severity=sev,
                category="Exploit" if i < 3 else "Scanning",
            )
        )
        
    stats = await crud.get_alert_stats(db_session)
    assert stats.total == 5
    assert stats.critical == 2
    assert stats.high == 1
    assert stats.medium == 1
    assert stats.low == 1
    assert stats.unique_sources == 5
    assert len(stats.top_categories) > 0
    assert stats.top_categories[0]["category"] == "Exploit"
    assert stats.top_categories[0]["count"] == 3


@pytest.mark.asyncio
async def test_crud_delete_all_alerts(db_session):
    """Ensure delete_all_alerts cleanly resets the table."""
    await crud.create_alert(
        db_session,
        AlertCreate(
            source_ip="198.51.100.1",
            dest_ip="192.168.1.1",
            alert_type="Temporary Alert",
            severity=SeverityEnum.LOW,
        )
    )
    assert len(await crud.get_alerts(db_session)) == 1
    
    await crud.delete_all_alerts(db_session)
    assert len(await crud.get_alerts(db_session)) == 0


# ============================================================================
# 6. API Input Validation & Contract Regressions
# ============================================================================

@pytest.mark.asyncio
async def test_api_list_alerts_invalid_ip_query_param(client, auth_headers):
    """Ensure passing invalid IP to ?source_ip= returns 400 Bad Request."""
    response = await client.get("/api/v1/alerts/?source_ip=invalid_ip_address", headers=auth_headers)
    assert response.status_code == 400
    assert "Invalid IP address" in response.json()["detail"]


@pytest.mark.asyncio
async def test_api_get_nonexistent_alert_returns_404(client, auth_headers):
    """Ensure fetching non-existent alert returns 404 Not Found."""
    response = await client.get("/api/v1/alerts/999999", headers=auth_headers)
    assert response.status_code == 404
    assert "Alert not found" in response.json()["detail"]
