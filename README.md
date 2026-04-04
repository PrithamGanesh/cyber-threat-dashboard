# LiveSOC — Real-Time Security Operations Center

> A full-stack cybersecurity dashboard for ingesting, scoring, and visualising network alerts in real time.

## Architecture

Traffic → Suricata/Zeek → Log Parser → FastAPI Backend → Redis (Pub/Sub)
↓
PostgreSQL
↓
React Frontend

## Stack

| Layer | Technology |
|-------|-----------|
| IDS | Suricata 7 / Zeek 6 |
| Backend | FastAPI (Python 3.12) + asyncpg |
| Database | PostgreSQL 16 |
| Streaming | Redis 7 Pub/Sub → SSE |
| Frontend | React 18 + Vite + Leaflet |
| Container | Docker Compose |

## Quick Start
```bash
cp .env.example .env        # edit keys if desired
docker-compose up --build   # starts all services
# Frontend: http://localhost:3000
# API docs: http://localhost:8000/docs
```

## Simulate Attacks
```bash
pip install httpx
python scripts/simulate_attack.py --count 50 --delay 0.2
```

## Generate Sample Logs
```bash
python scripts/log_generator.py --lines 1000 --out sample-data/eve.json
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/alerts/` | List alerts (filterable) |
| GET | `/api/v1/alerts/stats` | Aggregated stats |
| GET | `/api/v1/alerts/stream` | SSE live stream |
| POST | `/api/v1/alerts/ingest` | Ingest raw log |
| GET | `/api/v1/health/` | System health |

## Features

- **Real-time streaming** via Redis Pub/Sub → Server-Sent Events
- **Risk scoring engine** — severity + category + IP heuristics
- **GeoIP enrichment** — ip-api.com (free) or AbuseIPDB (optional API key)
- **Dark tactical UI** — sortable table, live feed ticker, world attack map
- **Simulation scripts** — generate realistic attack traffic without a live IDS