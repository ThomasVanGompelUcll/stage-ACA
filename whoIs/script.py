import whois
import requests
import re


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if v and str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _extract_emails(whois_record):
    emails = []
    for key in ("emails", "email"):
        if hasattr(whois_record, key):
            emails.extend(_as_list(getattr(whois_record, key, None)))

    if not emails:
        text_blob = ""
        if hasattr(whois_record, "text") and whois_record.text:
            text_blob = str(whois_record.text)
        elif isinstance(whois_record, dict):
            text_blob = "\n".join(str(v) for v in whois_record.values() if v)

        if text_blob:
            emails.extend(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text_blob))

    return sorted(set(e.lower() for e in emails if "@" in e))

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "emails": _extract_emails(w),
            "org": w.org,
            "name": w.name,
            "registrar": w.registrar,
            "nameservers": _as_list(w.name_servers),
        }
    except Exception as e:
        print(f"[WHOIS ERROR] {domain}: {e}")
        return None


def find_domains_by_term(term):
    """
    Gratis reverse-WHOIS lookup via ViewDNS HTML endpoint (geen API key).
    """
    if not term:
        return []

    try:
        url = f"https://viewdns.info/reversewhois/?q={term}"
        res = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=20)

        if res.status_code != 200:
            print(f"[LOOKUP WARNING] ViewDNS status {res.status_code} voor '{term}'")
            return []

        if "No records found" in res.text:
            return []

        matches = re.findall(
            r'<tr><td class="[^"]*font-medium[^"]*">([^<]+)</td><td class="',
            res.text,
            re.IGNORECASE,
        )

        valid_domains = []
        for candidate in matches:
            domain_candidate = candidate.strip().lower()
            if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}", domain_candidate):
                valid_domains.append(domain_candidate)

        return sorted(set(valid_domains))
    except requests.RequestException as e:
        print(f"[LOOKUP ERROR] '{term}': {e}")
        return []


def discover_more_domains(domain):
    info = get_whois_info(domain)
    if not info:
        return []

    found = set()
    lookup_terms = []

    for email in info["emails"]:
        lookup_terms.append(email)
        new_domains = find_domains_by_term(email)
        for d in new_domains:
            found.add(d)

    for term in _as_list(info.get("name")) + _as_list(info.get("org")):
        if len(term) >= 4:
            lookup_terms.append(term)
            for d in find_domains_by_term(term):
                found.add(d)

    if not lookup_terms:
        print("[WHOIS INFO] Geen bruikbare WHOIS-termen (email/naam/org) voor reverse lookup.")

    if not found:
        print("[WHOIS INFO] Geen gerelateerde domeinen gevonden via openbare reverse-WHOIS bronnen.")

    found.discard(domain.lower())
    return sorted(found)
