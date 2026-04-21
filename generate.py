#!/usr/bin/env python3
import os
import json
import requests

URLS = {
    "v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "v6": "https://www.spamhaus.org/drop/drop_v6.json"
}

OUTPUT_DIR = "output"


# -----------------------------
# Fetch with fallback parsing
# -----------------------------
def fetch(url):
    r = requests.get(url, timeout=20)
    r.raise_for_status()

    text = r.text.strip()

    cidrs = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        # пробуємо JSON рядок
        try:
            obj = json.loads(line)

            if isinstance(obj, dict):
                cidr = obj.get("cidr")
                if cidr:
                    cidrs.append(cidr)

            continue
        except:
            pass

        # fallback: plain CIDR
        if "/" in line:
            cidrs.append(line.split()[0])

    return cidrs
# -----------------------------
# ipset generator
# -----------------------------
def generate_ipset(name, cidrs, family):
    lines = [f"create {name} hash:net family {family}"]
    for c in cidrs:
        lines.append(f"add {name} {c}")
    return "\n".join(lines)


# -----------------------------
# MikroTik generator
# -----------------------------
def generate_mikrotik(list_name, cidrs):
    lines = [
        f"/ip firewall address-list remove [find list={list_name}]"
    ]

    for c in cidrs:
        lines.append(
            f"/ip firewall address-list add list={list_name} address={c}"
        )

    return "\n".join(lines)


# -----------------------------
# MAIN
# -----------------------------
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    v4 = fetch(URLS["v4"])
    v6 = fetch(URLS["v6"])

    v4 = [x for x in v4 if x]
    v6 = [x for x in v6 if x]

    print(f"[+] IPv4: {len(v4)} networks")
    print(f"[+] IPv6: {len(v6)} networks")

    # ---------------- IPSET ----------------
    with open(f"{OUTPUT_DIR}/spamhaus_v4.ipset", "w") as f:
        f.write(generate_ipset("spamhaus_v4", v4, "inet"))

    with open(f"{OUTPUT_DIR}/spamhaus_v6.ipset", "w") as f:
        f.write(generate_ipset("spamhaus_v6", v6, "inet6"))

    # ---------------- MikroTik ----------------
    with open(f"{OUTPUT_DIR}/spamhaus_v4.rsc", "w") as f:
        f.write(generate_mikrotik("spamhaus_v4", v4))

    with open(f"{OUTPUT_DIR}/spamhaus_v6.rsc", "w") as f:
        f.write(generate_mikrotik("spamhaus_v6", v6))


if __name__ == "__main__":
    main()
