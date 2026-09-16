#!/usr/bin/env python3
import os
import json
import requests
import ipaddress

URLS = {
    "v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "v6": "https://www.spamhaus.org/drop/drop_v6.json"
}

OUTPUT_DIR = "output"

# family, table, set  для nftables
NFT_PARAMS = {
    "v4": ("ip", "firewall", "spamhaus_v4", "ipv4_addr"),
    "v6": ("ip6", "firewall6", "spamhaus_v6", "ipv6_addr"),
}


def fetch(url):
    r = requests.get(url, timeout=20)
    r.raise_for_status()

    text = r.text.strip()

    cidrs = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        # проба JSON-рядка
        try:
            obj = json.loads(line)

            if isinstance(obj, dict) and "cidr" in obj:
                cidrs.append(obj["cidr"])

            continue
        except Exception:
            pass

        # fallback (на випадок plain text)
        if "/" in line:
            cidrs.append(line.split()[0])

    # фінальна валідація
    clean = []
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
            clean.append(c)
        except Exception:
            continue

    return sorted(set(clean))


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

    return "\n".join(lines) + "\n"


def generate_ipset(cidrs, version):
    family = "inet" if version == "v4" else "inet6"
    name = f"spamhaus_{version}"

    lines = [f"create {name} hash:net family {family} -exist"]

    for c in cidrs:
        lines.append(f"add {name} {c}")

    return "\n".join(lines) + "\n"


def generate_nftables(cidrs, version):
    family, table, set_name, addr_type = NFT_PARAMS[version]

    lines = [
        f"add table {family} {table}",
        f"add set {family} {table} {set_name} "
        f"{{ type {addr_type}; flags interval; }}",
        f"flush set {family} {table} {set_name}",
    ]

    if cidrs:
        lines.append(f"add element {family} {table} {set_name} {{")
        lines.append(",\n".join(f"    {c}" for c in cidrs))
        lines.append("}")

    return "\n".join(lines) + "\n"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for version, url in URLS.items():
        cidrs = fetch(url)

        print(f"{version}: {len(cidrs)} networks")

        # MikroTik
        with open(f"{OUTPUT_DIR}/spamhaus_{version}.rsc", "w") as f:
            f.write(generate_mikrotik(cidrs, version))

        # ipset
        with open(f"{OUTPUT_DIR}/spamhaus_{version}.ipset", "w") as f:
            f.write(generate_ipset(cidrs, version))

        # nftables
        with open(f"{OUTPUT_DIR}/spamhaus_{version}.nft", "w") as f:
            f.write(generate_nftables(cidrs, version))


if __name__ == "__main__":
    main()
