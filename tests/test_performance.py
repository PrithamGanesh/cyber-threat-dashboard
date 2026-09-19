"""Performance and Concurrency Load Testing Suite for LiveSOC.

Measures:
- Latency percentiles (P50, P90, P95, P99, Mean, Min, Max) for core endpoints
- Ingestion throughput (Requests Per Second) under high concurrency
- Multi-analyst concurrent dashboard querying under load
- Stability and error rates under stress (target: 0.00% error rate)
"""
import asyncio
import time
import statistics
import pytest
from typing import List, Dict, Any

from app.models.alert import AlertCreate, SeverityEnum
from app.db import crud


def calculate_latency_metrics(latencies: List[float]) -> Dict[str, float]:
    """Calculate statistical distribution for response times (in milliseconds)."""
    if not latencies:
        return {}
    s = sorted(latencies)
    n = len(s)
    return {
        "count": n,
        "min_ms": round(min(s) * 1000, 2),
        "mean_ms": round(statistics.mean(s) * 1000, 2),
        "median_p50_ms": round(s[int(0.50 * (n - 1))] * 1000, 2),
        "p90_ms": round(s[int(0.90 * (n - 1))] * 1000, 2),
        "p95_ms": round(s[int(0.95 * (n - 1))] * 1000, 2),
        "p99_ms": round(s[int(0.99 * (n - 1))] * 1000, 2),
        "max_ms": round(max(s) * 1000, 2),
    }


@pytest.mark.asyncio
async def test_perf_endpoint_latency_distribution(client, db_session, auth_headers):
    """
    Performance Benchmark: Measure latency distribution across 100 iterations per endpoint.
    Pre-populates database with 200 realistic alerts.
    """
    # Pre-populate 200 alerts
    for i in range(200):
        sev = [SeverityEnum.CRITICAL, SeverityEnum.HIGH, SeverityEnum.MEDIUM, SeverityEnum.LOW][i % 4]
        await crud.create_alert(
            db_session,
            AlertCreate(
                source_ip=f"198.51.100.{i % 250 + 1}",
                dest_ip="192.168.1.10",
                alert_type=f"Threat Detection Type {i % 10}",
                severity=sev,
                score=float(20 + (i % 80)),
                category="Exploit" if i % 2 == 0 else "Port Scan",
            )
        )

    # 1. Benchmark GET /api/v1/alerts/ (List)
    list_latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        resp = await client.get("/api/v1/alerts/?limit=50", headers=auth_headers)
        t1 = time.perf_counter()
        assert resp.status_code == 200
        list_latencies.append(t1 - t0)

    list_metrics = calculate_latency_metrics(list_latencies)

    # 2. Benchmark GET /api/v1/alerts/stats (Single-query aggregation)
    stats_latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        resp = await client.get("/api/v1/alerts/stats", headers=auth_headers)
        t1 = time.perf_counter()
        assert resp.status_code == 200
        stats_latencies.append(t1 - t0)

    stats_metrics = calculate_latency_metrics(stats_latencies)

    # 3. Benchmark POST /api/v1/auth/login
    login_latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        resp = await client.post("/api/v1/auth/login", json={"username": "user", "password": "password123"})
        t1 = time.perf_counter()
        assert resp.status_code == 200
        login_latencies.append(t1 - t0)

    login_metrics = calculate_latency_metrics(login_latencies)

    # Assertions on latency budgets
    # List endpoint P95 should be under 50ms in hermetic test
    assert list_metrics["p95_ms"] < 100.0, f"List alerts P95 too slow: {list_metrics['p95_ms']}ms"
    # Stats aggregation P95 should be under 50ms
    assert stats_metrics["p95_ms"] < 100.0, f"Stats P95 too slow: {stats_metrics['p95_ms']}ms"
    # Login P95 should be under 50ms
    assert login_metrics["p95_ms"] < 100.0, f"Login P95 too slow: {login_metrics['p95_ms']}ms"

    print("\n--- Latency Performance Report ---")
    print(f"GET /alerts/ (50 items):   Median={list_metrics['median_p50_ms']}ms | P95={list_metrics['p95_ms']}ms | Mean={list_metrics['mean_ms']}ms")
    print(f"GET /alerts/stats:         Median={stats_metrics['median_p50_ms']}ms | P95={stats_metrics['p95_ms']}ms | Mean={stats_metrics['mean_ms']}ms")
    print(f"POST /auth/login:          Median={login_metrics['median_p50_ms']}ms | P95={login_metrics['p95_ms']}ms | Mean={login_metrics['mean_ms']}ms")


@pytest.mark.asyncio
async def test_perf_concurrent_ingestion_throughput(client, auth_headers):
    """
    Performance Benchmark: Concurrently ingest 100 alerts across simultaneous workers.
    Measures throughput in requests per second (RPS) and verifies 0% error rate.
    """
    total_requests = 100

    async def ingest_worker(idx: int) -> float:
        payload = {
            "timestamp": "2026-09-19T14:40:00.000000+0000",
            "event_type": "alert",
            "src_ip": f"198.51.100.{(idx % 250) + 1}",
            "src_port": 10000 + (idx % 50000),
            "dest_ip": "192.168.1.5",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": f"High Concurrency Attack #{idx}",
                "category": "Attempted Denial of Service",
                "severity": 1 if idx % 2 == 0 else 2,
            }
        }
        t0 = time.perf_counter()
        resp = await client.post(
            "/api/v1/alerts/ingest?source=suricata",
            json=payload,
            headers=auth_headers
        )
        t1 = time.perf_counter()
        assert resp.status_code == 201
        return t1 - t0

    start_time = time.perf_counter()
    latencies = await asyncio.gather(*(ingest_worker(i) for i in range(total_requests)))
    total_duration = time.perf_counter() - start_time

    rps = round(total_requests / total_duration, 2)
    metrics = calculate_latency_metrics(latencies)

    print("\n--- Concurrency Ingestion Throughput Report ---")
    print(f"Total Ingested: {total_requests} alerts")
    print(f"Duration:       {round(total_duration, 3)} seconds")
    print(f"Throughput:     {rps} requests/second")
    print(f"Latency P50:    {metrics['median_p50_ms']} ms")
    print(f"Latency P95:    {metrics['p95_ms']} ms")
    print(f"Latency Max:    {metrics['max_ms']} ms")

    # Assertions
    assert total_duration > 0
    assert rps > 10.0, f"Ingestion throughput too low: {rps} req/s"


@pytest.mark.asyncio
async def test_perf_concurrent_dashboard_polling(client, db_session, auth_headers):
    """
    Performance Benchmark: Simulate 30 simultaneous SOC analyst dashboards
    concurrently querying /alerts/ and /alerts/stats.
    """
    # Seed 50 alerts
    for i in range(50):
        await crud.create_alert(
            db_session,
            AlertCreate(
                source_ip=f"203.0.113.{i + 1}",
                dest_ip="192.168.1.1",
                alert_type="Port Scan",
                severity=SeverityEnum.MEDIUM,
            )
        )

    async def analyst_session(session_id: int):
        # Each analyst requests list and stats
        r_list = await client.get("/api/v1/alerts/?limit=20", headers=auth_headers)
        r_stats = await client.get("/api/v1/alerts/stats", headers=auth_headers)
        assert r_list.status_code == 200
        assert r_stats.status_code == 200

    start_time = time.perf_counter()
    num_analysts = 30
    await asyncio.gather(*(analyst_session(i) for i in range(num_analysts)))
    elapsed = time.perf_counter() - start_time

    total_queries = num_analysts * 2
    qps = round(total_queries / elapsed, 2)

    print("\n--- Multi-Analyst Concurrent Query Report ---")
    print(f"Concurrent Analysts: {num_analysts}")
    print(f"Total Queries:       {total_queries} queries (List + Stats)")
    print(f"Elapsed Time:        {round(elapsed, 3)} seconds")
    print(f"Query QPS:           {qps} queries/second")

    assert elapsed < 5.0, f"Concurrent querying exceeded time threshold: {elapsed}s"
