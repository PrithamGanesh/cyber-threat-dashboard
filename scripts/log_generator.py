#!/usr/bin/env python3
"""
Generate a synthetic Suricata EVE JSON log file.
Usage: python log_generator.py --out sample-data/eve.json --lines 500
"""
import argparse, json, random
from datetime import datetime, timezone, timedelta

# (same SIGNATURES / COUNTRIES as simulate_attack.py)
SIGNATURES = [
    ("ET EXPLOIT Apache Log4Shell RCE", "exploit", 1),
    ("ET MALWARE Cobalt Strike Beacon", "malware", 1),
    ("ET SCAN Nmap Aggressive Scan", "scan", 3),
    ("ET DOS HTTP Flood", "dos", 2),
    ("ET TROJAN Metasploit Meterpreter", "trojan", 1),
]

def gen_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def gen_line(ts):
    sig, cat, sev = random.choice(SIGNATURES)
    return {
        "timestamp": ts.isoformat(),
        "event_type": "alert",
        "src_ip": gen_ip(),
        "src_port": random.randint(1024, 65535),
        "dest_ip": f"192.168.1.{random.randint(1,50)}",
        "dest_port": random.choice([80, 443, 22, 3389]),
        "proto": "TCP",
        "alert": {"signature": sig, "category": cat, "severity": sev},
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="sample-data/eve.json")
    parser.add_argument("--lines", type=int, default=500)
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    lines = []
    for i in range(args.lines):
        ts = now - timedelta(seconds=(args.lines - i) * 6)
        lines.append(json.dumps(gen_line(ts)))

    with open(args.out, "w") as f:
        f.write("\n".join(lines))
    print(f"Wrote {args.lines} log lines → {args.out}")

if __name__ == "__main__":
    main()