#!/usr/bin/env python3
import os
import json
import requests

URLS = {
    "v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "v6": "https://www.spamhaus.org/drop/drop_v6.json"
}

OUTPUT_DIR = "output"

def fetch(url):
    r = requests.get(url, timeout=20)
    r.raise_for_status()

    data = r.json()

    cidrs = []

    drops = data.get("drops", []) if isinstance(data, dict) else data

    for item in drops:
        if isinstance(item, dict):
            cidr = item.get("cidr")
        else:
            cidr = item

        if not cidr:
            continue

        # 🔥 ФІЛЬТР: тільки валідний IPv6/IPv4 CIDR
        try:
            ipaddress.ip_network(cidr, strict=False)
            cidrs.append(cidr)
        except:
            continue

    return cidrs
def generate_mikrotik(cidrs, version):
    lines = []

    if version == "v4":
        base = "/ip firewall address-list"
    else:
        base = "/ipv6 firewall address-list"

    list_name = f"spamhaus_{version}"

    lines.append(f"{base} remove [find list={list_name}]")

    for c in cidrs:
        lines.append(f"{base} add list={list_name} address={c}")

    return "\n".join(lines)


def generate_ipset(cidrs, version):
    family = "inet" if version == "v4" else "inet6"
    name = f"spamhaus_{version}"

    lines = [f"create {name} hash:net family {family}"]

    for c in cidrs:
        lines.append(f"add {name} {c}")

    return "\n".join(lines)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for version, url in URLS.items():
        cidrs = fetch(url)
        cidrs = list(set(cidrs))  # дедуп

        print(f"{version}: {len(cidrs)} networks")

        # MikroTik
        with open(f"{OUTPUT_DIR}/spamhaus_{version}.rsc", "w") as f:
            f.write(generate_mikrotik(cidrs, version))

        # ipset
        with open(f"{OUTPUT_DIR}/spamhaus_{version}.ipset", "w") as f:
            f.write(generate_ipset(cidrs, version))


if __name__ == "__main__":
    main()
