import csv
import re
from collections import defaultdict

import requests

try:
    import dns.resolver
except Exception:
    dns = None


def parse_dns_csv(dns_csv_path):
    dns_records = defaultdict(lambda: defaultdict(list))
    if not dns_csv_path.exists():
        return dns_records

    with dns_csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip().lower()
            rtype = row.get("record_type", "").strip().upper()
            value = row.get("value", "").strip()
            if domain and rtype and value:
                dns_records[domain][rtype].append(value)

    return dns_records


def resolve_dns_values(name, rtype, timeout=3):
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=timeout)
        return [str(answer).strip() for answer in answers if str(answer).strip()]
    except Exception:
        return []


def reverse_ip_lookup(ip):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        res = requests.get(url, timeout=20)
        if res.status_code != 200:
            return []
        text = res.text
        if "API count exceeded" in text or "error" in text.lower():
            return []
        domains = []
        for line in text.splitlines():
            value = line.strip().lower()
            if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}", value):
                domains.append(value)
        return sorted(set(domains))
    except requests.RequestException:
        return []


def build_reverse_ip_clusters(dns_records):
    ip_to_hosts = defaultdict(set)
    for host, records in dns_records.items():
        for ip in records.get("A", []):
            ip_to_hosts[ip].add(host)

    rows = []
    for ip in sorted(ip_to_hosts):
        local_hosts = sorted(ip_to_hosts[ip])
        external_hosts = reverse_ip_lookup(ip)
        rows.append(
            {
                "ip": ip,
                "local_hosts_count": len(local_hosts),
                "local_hosts": "; ".join(local_hosts),
                "external_hosts_count": len(external_hosts),
                "external_hosts": "; ".join(external_hosts[:100]),
            }
        )
    return rows, sorted(ip_to_hosts.keys())


def lookup_asn_ipinfo(ip, token=None):
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Accept": "application/json"}
    params = {"token": token} if token else {}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=15)
        if res.status_code != 200:
            return {}
        data = res.json()
        org = data.get("org", "")
        asn = ""
        if org and org.upper().startswith("AS"):
            asn = org.split(" ", 1)[0]
        return {
            "ip": ip,
            "asn": asn,
            "org": org,
            "hostname": data.get("hostname", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
        }
    except requests.RequestException:
        return {}
