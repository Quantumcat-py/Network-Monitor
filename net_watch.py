import os
import time
from datetime import datetime
from collections import defaultdict

LOG_FILE = "soc_network_log.txt"

prev = set()
ip_counter = defaultdict(int)

def get_ip(line):
    parts = line.split()
    for p in parts:
        if "." in p and any(c.isdigit() for c in p):
            return p.split(":")[0]
    return None

while True:
    output = set(os.popen("ss -tun").read().splitlines()

    output = set(output[1:])
    
    new = output - prev

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "="*60)
    print(f" SOC NETWORK ANALYST - {timestamp}")
    print("="*60)

    if new:
        for line in new:
            ip = get_ip(line)

            if ip:
                ip_counter[ip] += 1

               if ip.startswith(("10.", "192.168.", "127.")):
                    tag = "LOCAL"
                else:
                    tag = "EXTERNAL"

                print(f"[NEW] [{tag}] {ip}")
                print(f"      {line}")

                with open(LOG_FILE, "a") as f:
                    f.write(f"{timestamp} | {tag} | {ip} | {line}\n")

    else:
        print("No new connections detected.")

    print("\nTop Talked IPs:")
    for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} -> {count} events")

    prev = output
    time.sleep(3)
