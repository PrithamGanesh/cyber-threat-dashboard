#!/usr/bin/env python3
"""
Simulate attack traffic by POSTing Suricata-style EVE JSON to the backend.
Usage: python simulate_attack.py --url http://localhost:8000 --count 50
"""
import argparse, asyncio, random, json
from datetime import datetime, timezone
import httpx

SIGNATURES = [
    ("ET EXPLOIT Apache Log4Shell RCE", "exploit", 1),
    ("ET MALWARE Cobalt Strike Beacon", "malware", 1),
    ("ET SCAN Nmap Aggressive Scan", "scan", 3),
    ("ET DOS HTTP Flood", "dos", 2),
    ("ET TROJAN Metasploit Meterpreter", "trojan", 1),
    ("ET CREDS SSH Brute Force", "brute force", 2),
    ("ET WEB_SERVER SQL Injection", "sql injection", 2),
    ("ET INFO Possible Tor Usage", "suspicious connection", 3),
    ("ET POLICY Cryptocurrency Miner", "policy", 3),
    ("GPL ATTACK_RESPONSE id check", "shellcode", 2),
]

COUNTRIES = [
    ("Russia", "Moscow", 55.75, 37.61),
    ("China", "Beijing", 39.90, 116.40),
    ("United States", "Chicago", 41.85, -87.65),
    ("Germany", "Frankfurt", 50.11, 8.68),
    ("Brazil", "São Paulo", -23.54, -46.63),
    ("Romania", "Bucharest", 44.43, 26.10),
    ("India", "Mumbai", 19.07, 72.87),
    ("Netherlands", "Amsterdam", 52.37, 4.89),
]

DEST_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.1", "192.168.0.1"]


def gen_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def build_eve(sig, category, severity_num, country_info):
    country, city, lat, lon = country_info
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "alert",
        "src_ip": gen_ip(),
        "src_port": random.randint(1024, 65535),
        "dest_ip": random.choice(DEST_IPS),
        "dest_port": random.choice([80, 443, 22, 3389, 8080, 4444]),
        "proto": random.choice(["TCP", "UDP"]),
        "alert": {
            "signature": sig,
            "category": category,
            "severity": severity_num,
        },
        # inject geo for simulation
        "_geo": {"country": country, "city": city, "lat": lat, "lon": lon},
    }


async def send_event(client, url, event):
    try:
        r = await client.post(f"{url}/api/v1/alerts/ingest", json=event, params={"source": "suricata"})
        print(f"  [{r.status_code}] {event['alert']['signature'][:55]}")
    except Exception as e:
        print(f"  [ERR] {e}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.3)
    args = parser.parse_args()

    print(f"Simulating {args.count} attack events → {args.url}")
    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(args.count):
            sig, category, sev = random.choice(SIGNATURES)
            country_info = random.choice(COUNTRIES)
            event = build_eve(sig, category, sev, country_info)
            await send_event(client, args.url, event)
            await asyncio.sleep(args.delay)

    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())