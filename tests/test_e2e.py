"""End-to-End (E2E) Lifecycle Test Suite for LiveSOC.

Tests complete workflows from authentication and IDS ingestion to storage,
aggregation, enrichment, and administrative cleanup.
"""
import pytest
from app.core.config import settings


@pytest.mark.asyncio
async def test_e2e_suricata_alert_full_lifecycle(client):
    """
    E2E Test: Full lifecycle of a Suricata IDS alert:
    1. Authenticate via /api/v1/auth/login
    2. Ingest raw Suricata EVE log entry
    3. Verify parsing, scoring, GeoIP enrichment, and persistence
    4. Query alert list and verify filter match
    5. Fetch alert by specific ID
    6. Verify statistical aggregation reflects the new alert
    7. Verify system health reporting
    8. Execute administrative reset and verify clean slate
    """
    # Step 1: Authenticate
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "user", "password": "password123"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Step 2: Ingest Suricata EVE Log
    suricata_log = {
        "timestamp": "2026-09-19T14:30:00.000000+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.42",
        "src_port": 49152,
        "dest_ip": "192.168.1.10",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010935,
            "rev": 3,
            "signature": "ET MALWARE Win32/CobaltStrike Beacon",
            "category": "A Network Trojan was detected",
            "severity": 1
        }
    }

    ingest_resp = await client.post(
        "/api/v1/alerts/ingest?source=suricata",
        json=suricata_log,
        headers=auth_headers
    )
    assert ingest_resp.status_code == 201
    created_alert = ingest_resp.json()
    alert_id = created_alert["id"]

    # Step 3: Validate ingested alert fields
    assert alert_id > 0
    assert created_alert["source_ip"] == "198.51.100.42"
    assert created_alert["dest_ip"] == "192.168.1.10"
    assert created_alert["severity"] == "critical"
    assert created_alert["score"] > 80.0
    assert created_alert["country"] == "United States"
    assert created_alert["city"] == "San Jose"
    assert created_alert["latitude"] is not None
    assert created_alert["longitude"] is not None
    assert created_alert["signature"] == "ET MALWARE Win32/CobaltStrike Beacon"

    # Step 4: Query alerts list and filter by severity
    list_resp = await client.get("/api/v1/alerts/?severity=critical", headers=auth_headers)
    assert list_resp.status_code == 200
    alerts_list = list_resp.json()
    assert len(alerts_list) == 1
    assert alerts_list[0]["id"] == alert_id

    # Step 5: Fetch single alert by ID
    single_resp = await client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers)
    assert single_resp.status_code == 200
    assert single_resp.json()["id"] == alert_id

    # Step 6: Verify statistics
    stats_resp = await client.get("/api/v1/alerts/stats", headers=auth_headers)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total"] == 1
    assert stats["critical"] == 1
    assert stats["high"] == 0
    assert stats["unique_sources"] == 1
    assert len(stats["top_categories"]) == 1
    assert stats["top_categories"][0]["category"] == "A Network Trojan was detected"

    # Step 7: Verify health check
    health_resp = await client.get("/api/v1/health/")
    assert health_resp.status_code == 200
    health = health_resp.json()
    assert health["status"] == "healthy"
    assert health["services"]["database"] == "ok"
    assert health["services"]["redis"] == "ok"

    # Step 8: Administrative reset
    admin_headers = {
        "Authorization": f"Bearer {token}",
        "admin-key": settings.ADMIN_API_KEY
    }
    reset_resp = await client.delete("/api/v1/alerts/reset", headers=admin_headers)
    assert reset_resp.status_code == 204

    # Verify table is empty
    empty_list = await client.get("/api/v1/alerts/", headers=auth_headers)
    assert empty_list.status_code == 200
    assert len(empty_list.json()) == 0


@pytest.mark.asyncio
async def test_e2e_zeek_suspicious_connection_lifecycle(client):
    """
    E2E Test: Ingest Zeek connection log and verify full detection pipeline.
    """
    # Authenticate
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Zeek connection on Metasploit reverse TCP handler port 4444
    zeek_log = {
        "ts": 1712234400.0,
        "uid": "CHk6513A1d0a5",
        "id.orig_h": "203.0.113.88",
        "id.orig_p": 51234,
        "id.resp_h": "10.0.0.5",
        "id.resp_p": 4444,
        "proto": "tcp",
        "service": None,
        "duration": 12.4,
        "orig_bytes": 4500,
        "resp_bytes": 89000,
        "conn_state": "SF"
    }

    ingest_resp = await client.post(
        "/api/v1/alerts/ingest?source=zeek",
        json=zeek_log,
        headers=auth_headers
    )
    assert ingest_resp.status_code == 201
    alert = ingest_resp.json()
    assert alert["source"] == "zeek"
    assert alert["dest_port"] == 4444
    assert alert["severity"] == "high"
    assert alert["score"] >= 60.0

    # Verify stats incremented
    stats_resp = await client.get("/api/v1/alerts/stats", headers=auth_headers)
    assert stats_resp.status_code == 200
    assert stats_resp.json()["high"] >= 1


@pytest.mark.asyncio
async def test_e2e_ingest_non_alert_rejected(client, auth_headers):
    """
    E2E Test: Verify non-alert logs (e.g. Suricata DNS query) return 422 Unprocessable Entity.
    """
    dns_log = {
        "timestamp": "2026-09-19T14:35:00.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.50",
        "src_port": 53535,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "google.com"}
    }
    response = await client.post(
        "/api/v1/alerts/ingest?source=suricata",
        json=dns_log,
        headers=auth_headers
    )
    assert response.status_code == 422
    assert "did not produce an alert" in response.json()["detail"]


@pytest.mark.asyncio
async def test_e2e_multi_alert_pagination_and_querying(client, auth_headers):
    """
    E2E Test: Ingest multiple diverse alerts, test pagination and composite filtering.
    """
    # Ingest 3 critical alerts and 2 high alerts
    for i in range(3):
        await client.post(
            "/api/v1/alerts/ingest?source=suricata",
            json={
                "event_type": "alert",
                "src_ip": f"198.51.100.{10 + i}",
                "dest_ip": "192.168.1.1",
                "src_port": 50000 + i,
                "dest_port": 443,
                "proto": "TCP",
                "alert": {
                    "signature": f"CVE-2024-999{i} Exploit",
                    "category": "Web Application Attack",
                    "severity": 1
                }
            },
            headers=auth_headers
        )

    for i in range(2):
        await client.post(
            "/api/v1/alerts/ingest?source=suricata",
            json={
                "event_type": "alert",
                "src_ip": f"203.0.113.{20 + i}",
                "dest_ip": "192.168.1.1",
                "src_port": 60000 + i,
                "dest_port": 22,
                "proto": "TCP",
                "alert": {
                    "signature": f"SSH Scan {i}",
                    "category": "Attempted Information Leak",
                    "severity": 2
                }
            },
            headers=auth_headers
        )

    # Test limit = 2
    page1 = await client.get("/api/v1/alerts/?limit=2&skip=0", headers=auth_headers)
    assert len(page1.json()) == 2

    # Test skip = 2
    page2 = await client.get("/api/v1/alerts/?limit=2&skip=2", headers=auth_headers)
    assert len(page2.json()) == 2
    # Ensure disjoint IDs
    assert page1.json()[0]["id"] != page2.json()[0]["id"]

    # Filter by specific source IP
    ip_filtered = await client.get("/api/v1/alerts/?source_ip=198.51.100.10", headers=auth_headers)
    assert len(ip_filtered.json()) == 1
    assert ip_filtered.json()[0]["source_ip"] == "198.51.100.10"
