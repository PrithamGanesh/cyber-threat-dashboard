import json
import logging
from typing import Optional, Dict, Any
from app.models.alert import AlertCreate
from app.services.scoring import calculate_score
from app.services.threat_intel import enrich_ip

logger = logging.getLogger(__name__)


def parse_suricata_eve(raw: Dict[str, Any]) -> Optional[AlertCreate]:
    """Parse a Suricata EVE JSON log entry into an AlertCreate."""
    try:
        event_type = raw.get("event_type", "")
        if event_type != "alert":
            return None

        alert_block = raw.get("alert", {})
        src_ip = raw.get("src_ip", "")
        dest_ip = raw.get("dest_ip", "")
        severity_num = alert_block.get("severity", 3)

        severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        severity = severity_map.get(severity_num, "low")

        score = calculate_score(severity, alert_block.get("category", ""), src_ip)

        return AlertCreate(
            source_ip=src_ip,
            dest_ip=dest_ip,
            source_port=raw.get("src_port"),
            dest_port=raw.get("dest_port"),
            protocol=raw.get("proto", "").upper(),
            alert_type=alert_block.get("signature", "Unknown"),
            severity=severity,
            score=score,
            signature=alert_block.get("signature", ""),
            category=alert_block.get("category", ""),
            raw_log=raw,
            source="suricata",
        )
    except Exception as e:
        logger.error(f"Failed to parse Suricata log: {e}")
        return None


def parse_zeek_conn(raw: Dict[str, Any]) -> Optional[AlertCreate]:
    """Parse a Zeek conn.log entry into an AlertCreate (suspicious connections only)."""
    try:
        # Flag connections with unusual ports or long durations as alerts
        dest_port = int(raw.get("id.resp_p", 0))
        duration = float(raw.get("duration", 0))
        orig_bytes = int(raw.get("orig_bytes", 0) or 0)

        suspicious_ports = {4444, 1337, 31337, 6666, 6667, 6668, 9001, 9030}
        is_suspicious = dest_port in suspicious_ports or (duration > 3600 and orig_bytes > 1_000_000)

        if not is_suspicious:
            return None

        src_ip = raw.get("id.orig_h", "")
        dest_ip = raw.get("id.resp_h", "")
        severity = "high" if dest_port in suspicious_ports else "medium"
        score = calculate_score(severity, "Suspicious Connection", src_ip)

        return AlertCreate(
            source_ip=src_ip,
            dest_ip=dest_ip,
            source_port=int(raw.get("id.orig_p", 0)),
            dest_port=dest_port,
            protocol=raw.get("proto", "").upper(),
            alert_type="Suspicious Connection",
            severity=severity,
            score=score,
            category="Suspicious Connection",
            raw_log=raw,
            source="zeek",
        )
    except Exception as e:
        logger.error(f"Failed to parse Zeek log: {e}")
        return None


async def parse_log_line(line: str, source: str = "suricata") -> Optional[AlertCreate]:
    """Parse a single log line and return an AlertCreate or None."""
    try:
        raw = json.loads(line.strip())
        if source == "suricata":
            alert = parse_suricata_eve(raw)
        elif source == "zeek":
            alert = parse_zeek_conn(raw)
        else:
            return None

        if alert:
            # Geo-enrich (non-blocking, best-effort)
            try:
                geo = await enrich_ip(alert.source_ip)
                if geo:
                    alert.country = geo.get("country")
                    alert.city = geo.get("city")
                    alert.latitude = geo.get("lat")
                    alert.longitude = geo.get("lon")
                    alert.threat_intel = geo
            except Exception:
                pass

        return alert
    except json.JSONDecodeError:
        logger.warning(f"Non-JSON log line from {source}: {line[:80]}")
        return None