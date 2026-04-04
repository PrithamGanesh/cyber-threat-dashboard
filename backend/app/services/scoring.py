"""
Risk scoring engine.
Base score from severity + category boosters + heuristic IP bonuses.
Final score is clamped to [0, 100].
"""

SEVERITY_SCORES = {
    "critical": 85,
    "high": 65,
    "medium": 40,
    "low": 15,
}

CATEGORY_BOOSTERS = {
    "exploit": 20,
    "malware": 20,
    "trojan": 20,
    "backdoor": 20,
    "ransomware": 25,
    "c2": 20,
    "command and control": 20,
    "dos": 15,
    "ddos": 15,
    "scan": 5,
    "probe": 5,
    "brute force": 10,
    "credential": 12,
    "sql injection": 15,
    "xss": 10,
    "shellcode": 18,
    "botnet": 18,
    "suspicious connection": 8,
}


def calculate_score(severity: str, category: str, source_ip: str = "") -> float:
    base = SEVERITY_SCORES.get(severity.lower(), 10)

    # Category booster (case-insensitive partial match)
    category_lower = (category or "").lower()
    boost = 0
    for keyword, value in CATEGORY_BOOSTERS.items():
        if keyword in category_lower:
            boost = max(boost, value)

    # Small heuristic: well-known bad port ranges in IP string (port reuse patterns)
    ip_boost = 0
    if source_ip:
        # Tor exit node heuristic — many exits start with specific octets (simplified)
        first_octet = int(source_ip.split(".")[0]) if "." in source_ip else 0
        if first_octet in range(185, 200):
            ip_boost = 5

    score = base + boost + ip_boost
    return float(min(max(score, 0), 100))


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 35:
        return "medium"
    return "low"