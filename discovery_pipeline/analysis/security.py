import re
from collections import defaultdict
from urllib.parse import urlparse

from discovery_pipeline.constants import CLOUD_ENDPOINT_PATTERNS, SEC_HEADERS, TAKEOVER_FINGERPRINTS
from discovery_pipeline.scanning.network import resolve_dns_values


DKIM_COMMON_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "mail",
    "smtp",
    "mta",
]


def _clean_txt_record(row):
    """Strip leading/trailing quotes and whitespace from DNS TXT records."""
    return row.strip().strip('"')


def discover_dkim_records(root_domain, selectors=None):
    found_selectors = []
    found_records = []
    selector_list = selectors or DKIM_COMMON_SELECTORS

    for selector in selector_list:
        host = f"{selector}._domainkey.{root_domain}"
        txt_rows = resolve_dns_values(host, "TXT")
        dkim_rows = [row for row in txt_rows if "v=dkim1" in _clean_txt_record(row).lower()]
        if dkim_rows:
            found_selectors.append(selector)
            found_records.extend([_clean_txt_record(row) for row in dkim_rows])

    return sorted(set(found_selectors)), found_records


def evaluate_email_security(root_domain):
    spf_txt = [_clean_txt_record(row) for row in resolve_dns_values(root_domain, "TXT") if _clean_txt_record(row).lower().startswith("v=spf1")]
    dmarc_txt = [_clean_txt_record(row) for row in resolve_dns_values(f"_dmarc.{root_domain}", "TXT") if _clean_txt_record(row).lower().startswith("v=dmarc1")]
    mta_sts_txt = [_clean_txt_record(row) for row in resolve_dns_values(f"_mta-sts.{root_domain}", "TXT") if _clean_txt_record(row).lower().startswith("v=stsv1")]
    tls_rpt_txt = [_clean_txt_record(row) for row in resolve_dns_values(f"_smtp._tls.{root_domain}", "TXT") if "v=tlsrptv1" in _clean_txt_record(row).lower()]
    mx_records = resolve_dns_values(root_domain, "MX")
    dkim_selectors, dkim_records = discover_dkim_records(root_domain)

    spf_record = spf_txt[0] if spf_txt else ""
    dmarc_record = dmarc_txt[0] if dmarc_txt else ""
    dkim_status = "present" if dkim_records else "missing"

    spf_mode = "missing"
    if spf_record:
        if "+all" in spf_record or " all" in spf_record and "-all" not in spf_record and "~all" not in spf_record:
            spf_mode = "unsafe"
        elif "~all" in spf_record:
            spf_mode = "softfail"
        elif "-all" in spf_record:
            spf_mode = "strict"
        else:
            spf_mode = "present"

    dmarc_policy = "missing"
    if dmarc_record:
        policy_match = re.search(r"\bp=([a-zA-Z]+)", dmarc_record, flags=re.IGNORECASE)
        if policy_match:
            dmarc_policy = policy_match.group(1).lower()
        else:
            dmarc_policy = "present"

    if dmarc_policy in {"reject", "quarantine"} and spf_mode == "strict" and dkim_status == "present":
        risk = "low"
    elif dmarc_policy in {"none", "missing"} or spf_mode in {"missing", "unsafe"} or dkim_status == "missing":
        risk = "high"
    else:
        risk = "medium"

    issues = []
    if not mx_records:
        issues.append("no-mx")
    if spf_mode in {"missing", "unsafe"}:
        issues.append("spf-weak-or-missing")
    if dmarc_policy in {"missing", "none"}:
        issues.append("dmarc-weak-or-missing")
    if not mta_sts_txt:
        issues.append("mta-sts-missing")
    if not tls_rpt_txt:
        issues.append("tls-rpt-missing")
    if dkim_status == "missing":
        issues.append("dkim-missing")

    return [
        {
            "domain": root_domain,
            "mx_count": len(mx_records),
            "mx_records": "; ".join(mx_records),
            "spf_mode": spf_mode,
            "spf_record": spf_record,
            "dmarc_policy": dmarc_policy,
            "dmarc_record": dmarc_record,
            "dkim_status": dkim_status,
            "dkim_selectors": "; ".join(dkim_selectors),
            "dkim_records": "; ".join(dkim_records[:5]),
            "mta_sts": "present" if mta_sts_txt else "missing",
            "tls_rpt": "present" if tls_rpt_txt else "missing",
            "risk_level": risk,
            "issues": ", ".join(issues),
        }
    ]


def detect_subdomain_takeover_risks(dns_records, web_rows):
    web_by_host_scheme = {(row.get("host", ""), row.get("scheme", "")): row for row in web_rows}
    rows = []

    for host in sorted(dns_records.keys()):
        cnames = dns_records.get(host, {}).get("CNAME", [])
        a_records = dns_records.get(host, {}).get("A", [])
        aaaa_records = dns_records.get(host, {}).get("AAAA", [])
        if not cnames:
            continue

        for cname in cnames:
            cname_lower = cname.lower().rstrip(".")
            provider = ""
            for fingerprint in TAKEOVER_FINGERPRINTS:
                if any(marker in cname_lower for marker in fingerprint["suffixes"]):
                    provider = fingerprint["provider"]
                    break

            if not provider:
                continue

            https_row = web_by_host_scheme.get((host, "https"), {})
            http_row = web_by_host_scheme.get((host, "http"), {})
            https_error = str(https_row.get("error", "")).lower()
            http_error = str(http_row.get("error", "")).lower()
            status_https = str(https_row.get("status", ""))
            status_http = str(http_row.get("status", ""))

            dangling_dns = not a_records and not aaaa_records
            err_signal = any(token in (https_error + " " + http_error) for token in ["nxdomain", "name or service not known", "no address associated"])
            http_signal = status_http in {"404", "410"} or status_https in {"404", "410"}

            if dangling_dns and (err_signal or http_signal):
                severity = "high"
                confidence = "medium"
                finding = "potential-takeover-candidate"
            elif dangling_dns:
                severity = "medium"
                confidence = "low"
                finding = "dangling-cname-to-third-party"
            else:
                continue

            rows.append(
                {
                    "host": host,
                    "cname": cname,
                    "provider": provider,
                    "finding": finding,
                    "severity": severity,
                    "confidence": confidence,
                    "recommendation": "Verify ownership of target service and remove dangling DNS record if unused",
                }
            )

    return rows


def compute_passive_vulnerability_indicators(web_rows, ssl_rows):
    ssl_by_host = {row.get("host", ""): row for row in ssl_rows}
    rows = []
    seen = set()

    for row in web_rows:
        host = row.get("host", "")
        scheme = row.get("scheme", "")
        status = str(row.get("status", ""))
        server = str(row.get("server", ""))
        x_powered = str(row.get("x_powered_by", ""))

        def add_issue(category, severity, indicator, evidence, recommendation):
            key = (host, category, indicator)
            if key in seen:
                return
            seen.add(key)
            rows.append(
                {
                    "host": host,
                    "category": category,
                    "severity": severity,
                    "indicator": indicator,
                    "evidence": evidence,
                    "recommendation": recommendation,
                }
            )

        if scheme == "http" and status.isdigit() and not row.get("error"):
            add_issue(
                "transport",
                "medium",
                "http-exposed",
                f"HTTP endpoint responds with status {status}",
                "Enforce HTTPS and redirect all HTTP requests",
            )

        if scheme == "https":
            missing = [h for h in SEC_HEADERS if row.get(h, "") in ("", "MISSING")]
            if len(missing) >= 3:
                add_issue(
                    "hardening",
                    "medium",
                    "missing-security-headers",
                    "Missing headers: " + ", ".join(missing),
                    "Set core security headers (HSTS, CSP, X-Frame-Options, etc.)",
                )

        if re.search(r"\d+\.\d+", server):
            add_issue(
                "banner",
                "low",
                "server-version-exposed",
                f"Server header: {server}",
                "Reduce version disclosure in web server banners",
            )

        if re.search(r"\d+\.\d+", x_powered):
            add_issue(
                "banner",
                "low",
                "x-powered-by-version-exposed",
                f"X-Powered-By: {x_powered}",
                "Disable or sanitize X-Powered-By header",
            )

    for host, ssl_info in ssl_by_host.items():
        if not ssl_info.get("ssl_ok"):
            rows.append(
                {
                    "host": host,
                    "category": "tls",
                    "severity": "high",
                    "indicator": "no-valid-ssl",
                    "evidence": ssl_info.get("error", "SSL handshake/certificate failure"),
                    "recommendation": "Deploy a valid TLS certificate chain",
                }
            )
            continue

        days_left = ssl_info.get("days_left")
        if isinstance(days_left, int) and days_left < 0:
            rows.append(
                {
                    "host": host,
                    "category": "tls",
                    "severity": "high",
                    "indicator": "expired-certificate",
                    "evidence": f"Certificate expired {abs(days_left)} days ago",
                    "recommendation": "Renew and deploy the certificate immediately",
                }
            )
        elif isinstance(days_left, int) and days_left <= 30:
            rows.append(
                {
                    "host": host,
                    "category": "tls",
                    "severity": "medium",
                    "indicator": "certificate-expiring-soon",
                    "evidence": f"Certificate expires in {days_left} days",
                    "recommendation": "Plan certificate renewal before expiry",
                }
            )

    rows.sort(key=lambda item: (item.get("host", ""), item.get("severity", ""), item.get("indicator", "")))
    return rows


def detect_cloud_misconfigurations(dns_records, web_rows):
    rows = []
    web_by_host = defaultdict(list)
    for row in web_rows:
        web_by_host[row.get("host", "")].append(row)

    for host in sorted(dns_records.keys()):
        cnames = dns_records.get(host, {}).get("CNAME", [])
        a_records = dns_records.get(host, {}).get("A", [])

        for cname in cnames:
            cname_l = cname.lower()
            for pattern in CLOUD_ENDPOINT_PATTERNS:
                if not any(marker in cname_l for marker in pattern["markers"]):
                    continue
                if not a_records:
                    rows.append(
                        {
                            "asset": host,
                            "provider": pattern["provider"],
                            "check": "dangling-cloud-alias",
                            "severity": "medium",
                            "status": "potential",
                            "evidence": f"CNAME {cname} without A/AAAA records",
                            "recommendation": "Remove unused DNS aliases or rebind to active managed resource",
                        }
                    )

    for host, host_rows in web_by_host.items():
        for row in host_rows:
            final_url = str(row.get("final_url", ""))
            parsed_host = urlparse(final_url).hostname if final_url else ""
            check_target = (parsed_host or host or "").lower()
            matched_provider = ""
            for pattern in CLOUD_ENDPOINT_PATTERNS:
                if any(marker in check_target for marker in pattern["markers"]):
                    matched_provider = pattern["provider"]
                    break
            if not matched_provider:
                continue

            status_code = str(row.get("status", ""))
            if status_code == "200" and not row.get("error"):
                rows.append(
                    {
                        "asset": host,
                        "provider": matched_provider,
                        "check": "public-cloud-endpoint",
                        "severity": "low",
                        "status": "review",
                        "evidence": f"Public {row.get('scheme', '')} endpoint returned 200 ({final_url or row.get('url', '')})",
                        "recommendation": "Confirm this exposure is intended and enforce least privilege",
                    }
                )

    rows.sort(key=lambda item: (item.get("severity", ""), item.get("asset", ""), item.get("check", "")))
    return rows
