import time

import requests


def run_whois_discovery(whois_module, domain):
    whois_info = whois_module.get_whois_info(domain) or {}
    related = whois_module.discover_more_domains(domain)
    return {
        "domain": domain,
        "emails": whois_info.get("emails", []) if isinstance(whois_info, dict) else [],
        "org": whois_info.get("org", "") if isinstance(whois_info, dict) else "",
        "name": whois_info.get("name", "") if isinstance(whois_info, dict) else "",
        "registrar": whois_info.get("registrar", "") if isinstance(whois_info, dict) else "",
        "nameservers": whois_info.get("nameservers", []) if isinstance(whois_info, dict) else [],
        "related_domains": sorted(set(d.lower() for d in related if d)),
    }


def is_valid_subdomain_for_domain(value, domain):
    import re

    candidate = value.strip().lower()
    if not candidate:
        return False
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if " " in candidate or "@" in candidate:
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", candidate):
        return False
    if ".." in candidate or candidate.startswith(".") or candidate.endswith("."):
        return False
    return candidate == domain or candidate.endswith(f".{domain}")


def normalize_subdomain_candidate(value, domain):
    candidate = (value or "").strip().lower().removeprefix("*.")
    if is_valid_subdomain_for_domain(candidate, domain):
        return candidate
    return ""


def fetch_subdomains_crtsh(domain, retries=3, timeout=25):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; discovery-pipeline/1.0)"}
    last_error = ""

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            names = set()
            for item in data:
                value = item.get("name_value", "") if isinstance(item, dict) else ""
                if not value:
                    continue
                for line in str(value).splitlines():
                    normalized = normalize_subdomain_candidate(line, domain)
                    if normalized:
                        names.add(normalized)
            return sorted(names), ""
        except Exception as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(min(5, attempt * 1.5))

    return [], last_error or "unknown error"


def fetch_subdomains_bufferover(domain, timeout=20):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        results = set()

        for key in ("FDNS_A", "RDNS"):
            for item in data.get(key, []) or []:
                text = str(item).strip()
                if not text:
                    continue
                parts = [part.strip() for part in text.split(",") if part.strip()]
                candidate = parts[-1] if parts else ""
                normalized = normalize_subdomain_candidate(candidate, domain)
                if normalized:
                    results.add(normalized)

        return sorted(results), ""
    except Exception as e:
        return [], str(e)


def fetch_subdomains_hackertarget(domain, timeout=20):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code != 200:
            return [], f"HTTP {response.status_code}"
        text = response.text.strip()
        if not text or "error" in text.lower() or "api count exceeded" in text.lower():
            return [], text[:200] if text else "empty response"

        results = set()
        for line in text.splitlines():
            parts = [part.strip() for part in line.split(",") if part.strip()]
            if not parts:
                continue
            normalized = normalize_subdomain_candidate(parts[0], domain)
            if normalized:
                results.add(normalized)

        return sorted(results), ""
    except Exception as e:
        return [], str(e)


def collect_ct_data(domain_module, domains):
    rows = []
    all_subdomains = set()
    source_logs = []

    for source_domain in domains:
        domain_subdomains = set()

        try:
            ct_items = domain_module.fetch_subdomains(source_domain)
            ct_error = ""
        except Exception as e:
            ct_items = []
            ct_error = str(e)

        if not ct_items:
            fallback_items, fallback_error = fetch_subdomains_crtsh(source_domain)
            ct_items = fallback_items
            if fallback_error and not ct_error:
                ct_error = fallback_error

        for sub in ct_items:
            cleaned = sub.strip().lower()
            if cleaned:
                domain_subdomains.add(cleaned)
                rows.append({"source_domain": source_domain, "discovered_name": cleaned, "source": "crt.sh"})

        source_logs.append(
            {
                "source_domain": source_domain,
                "source": "crt.sh",
                "status": "ok" if ct_items else "empty",
                "items": len(set(ct_items)),
                "error": ct_error,
            }
        )

        if not domain_subdomains:
            buffer_items, buffer_error = fetch_subdomains_bufferover(source_domain)
            for sub in buffer_items:
                domain_subdomains.add(sub)
                rows.append({"source_domain": source_domain, "discovered_name": sub, "source": "bufferover"})
            source_logs.append(
                {
                    "source_domain": source_domain,
                    "source": "bufferover",
                    "status": "ok" if buffer_items else "empty",
                    "items": len(buffer_items),
                    "error": buffer_error,
                }
            )

        if not domain_subdomains:
            ht_items, ht_error = fetch_subdomains_hackertarget(source_domain)
            for sub in ht_items:
                domain_subdomains.add(sub)
                rows.append({"source_domain": source_domain, "discovered_name": sub, "source": "hackertarget"})
            source_logs.append(
                {
                    "source_domain": source_domain,
                    "source": "hackertarget",
                    "status": "ok" if ht_items else "empty",
                    "items": len(ht_items),
                    "error": ht_error,
                }
            )

        if not domain_subdomains:
            print(f"[CT WARNING] {source_domain}: geen subdomeinen gevonden via crt.sh/bufferover/hackertarget")

        all_subdomains.update(domain_subdomains)

    rows = sorted(rows, key=lambda row: (row.get("source_domain", ""), row.get("source", ""), row.get("discovered_name", "")))
    return rows, sorted(all_subdomains), source_logs
