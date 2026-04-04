import httpx
import asyncio
import logging
from typing import Optional, Dict, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

# Simple in-memory cache to avoid hammering external APIs.
# NOTE: Cache is lost on application restart. For production, consider Redis cache.
# RATE LIMITING NOTE: ip-api.com (free tier) allows 45 requests/minute.
# AbuseIPDB (free tier) allows 1500 requests/day. Monitor cache hit rates.
_geo_cache: Dict[str, Any] = {}
_intel_cache: Dict[str, Any] = {}


async def enrich_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Enrich an IP address with geolocation and threat intelligence data.
    
    Performs lookups against free IP geolocation and optional threat databases.
    Results are cached in-memory to avoid repeated API calls.
    
    For private/RFC-1918 IPs, returns minimal data without external API calls.
    If external APIs are unavailable, returns partial or no enrichment (graceful degradation).
    
    Args:
        ip: IP address to enrich (IPv4 or IPv6)
    
    Returns:
        Dict with keys:
        - country, city, lat, lon, isp, org (from ip-api.com if available)
        - abuse_score, total_reports, is_whitelisted (from AbuseIPDB if key configured)
        - Returns None if enrichment failed and IP not in cache
    
    Note:
        Rate limits:
        - ip-api.com: 45 requests/minute (free tier)
        - AbuseIPDB: 1500 requests/day (free tier)
        Cache hit rate should be monitored in production.
    """
    # Check in-memory cache first
    if ip in _geo_cache:
        return _geo_cache[ip]

    result: Dict[str, Any] = {}

    # Skip private/loopback IPs to avoid unnecessary API calls
    if _is_private_ip(ip):
        private_result = {
            "country": "Private",
            "city": "LAN",
            "lat": 0.0,
            "lon": 0.0,
            "abuse_score": 0,
            "is_private": True,
        }
        _geo_cache[ip] = private_result
        return private_result

    # Geolocation lookup (free, no API key required)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            geo_resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "country,city,lat,lon,isp,org,mobile,proxy"},
                headers={"User-Agent": "LiveSOC/1.0"},
            )
            if geo_resp.status_code == 200:
                geo = geo_resp.json()
                if geo.get("status") == "success":
                    result.update({
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                        "isp": geo.get("isp"),
                        "org": geo.get("org"),
                        "is_mobile": geo.get("mobile"),
                        "is_proxy": geo.get("proxy"),
                    })
                else:
                    logger.debug(f"ip-api.com rejected lookup: {geo.get('message')}")
            else:
                logger.debug(f"ip-api.com returned {geo_resp.status_code}")
    except asyncio.TimeoutError:
        logger.debug(f"Geo lookup timeout for {ip}")
    except Exception as e:
        logger.debug(f"Geo lookup failed for {ip}: {e}")

    # Threat intelligence lookup (optional — only if API key configured)
    if settings.ABUSEIPDB_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                abuse_resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": "",
                    },
                )
                if abuse_resp.status_code == 200:
                    data = abuse_resp.json().get("data", {})
                    result.update({
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "is_whitelisted": data.get("isWhitelisted", False),
                    })
                else:
                    logger.debug(f"AbuseIPDB returned {abuse_resp.status_code}")
        except asyncio.TimeoutError:
            logger.debug(f"AbuseIPDB lookup timeout for {ip}")
        except Exception as e:
            logger.debug(f"AbuseIPDB lookup failed for {ip}: {e}")

    # Cache result (even if partial) to avoid repeated failed lookups
    _geo_cache[ip] = result or None
    return result or None


def _is_private_ip(ip: str) -> bool:
    """Check if IP address is private/internal (RFC-1918 or loopback).
    
    Args:
        ip: IP address to check
    
    Returns:
        True if IP is private/internal, False otherwise
    """
    private_prefixes = (
        "10.",           # 10.0.0.0/8
        "192.168.",      # 192.168.0.0/16
        "127.",          # 127.0.0.0/8 (loopback)
        "172.16.",       # 172.16.0.0/12
        "172.17.",
        "172.18.",
        "172.19.",
        "172.2",
        "172.3",
        "::1",           # IPv6 loopback
        "fe80",          # IPv6 link-local
    )
    return any(ip.startswith(p) for p in private_prefixes)