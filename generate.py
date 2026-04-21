#!/usr/bin/env python3
import requests
import os

os.makedirs("output", exist_ok=True)
URLS = {
    "v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "v6": "https://www.spamhaus.org/drop/drop_v6.json"
}

def fetch(url):
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json()

def parse(data):
    return [item["cidr"] for item in data["drops"]]

def generate_ipset(name, cidrs, family):
    lines = [f"create {name} hash:net family {family}"]
    for c in cidrs:
        lines.append(f"add {name} {c}")
    return "\n".join(lines)

def generate_mikrotik(list_name, cidrs):
    lines = [f"/ip firewall address-list remove [find list={list_name}]"]
    for c in cidrs:
        lines.append(f"/ip firewall address-list add list={list_name} address={c}")
    return "\n".join(lines)

def main():
    v4 = parse(fetch(URLS["v4"]))
    v6 = parse(fetch(URLS["v6"]))

    # ipset
    with open("output/spamhaus_v4.ipset", "w") as f:
        f.write(generate_ipset("spamhaus_v4", v4, "inet"))

    with open("output/spamhaus_v6.ipset", "w") as f:
        f.write(generate_ipset("spamhaus_v6", v6, "inet6"))

    # mikrotik
    with open("output/spamhaus_v4.rsc", "w") as f:
        f.write(generate_mikrotik("spamhaus_v4", v4))

    with open("output/spamhaus_v6.rsc", "w") as f:
        f.write(generate_mikrotik("spamhaus_v6", v6))

if __name__ == "__main__":
    main()
