from collections import defaultdict

from discovery_pipeline.constants import SEC_HEADERS
from discovery_pipeline.core.utils import is_under_official_domain


def fingerprint_assets(web_rows, asn_rows, dns_records, ssl_rows):
    asn_by_ip = {row.get("ip"): row for row in asn_rows}
    ssl_by_host = {row.get("host"): row for row in ssl_rows}

    fingerprints = []
    for row in web_rows:
        host = row["host"]
        schemes = row["scheme"]
        technologies = set()
        provider = ""
        frameworks = set()

        server = (row.get("server") or "").lower()
        powered = (row.get("x_powered_by") or "").lower()
        generator = (row.get("generator") or "").lower()
        title = (row.get("title") or "").lower()

        if "cloudflare" in server:
            provider = "Cloudflare"
        if "nginx" in server:
            technologies.add("nginx")
        if "apache" in server:
            technologies.add("apache")
        if "iis" in server:
            technologies.add("iis")

        if "php" in powered:
            frameworks.add("php")
        if "asp.net" in powered:
            frameworks.add("asp.net")
        if "express" in powered:
            frameworks.add("express")

        if "wordpress" in generator or "wordpress" in title:
            frameworks.add("wordpress")

        cnamerec = "; ".join(dns_records.get(host, {}).get("CNAME", []))
        if "cloudfront.net" in cnamerec:
            provider = provider or "AWS CloudFront"
        if "azure" in cnamerec:
            provider = provider or "Microsoft Azure"

        first_ip = ""
        a_records = dns_records.get(host, {}).get("A", [])
        if a_records:
            first_ip = a_records[0]
            asn_data = asn_by_ip.get(first_ip, {})
            if asn_data.get("org") and not provider:
                provider = asn_data["org"]

        ssl_info = ssl_by_host.get(host, {})
        if ssl_info.get("issuer"):
            technologies.add("tls")

        fingerprints.append(
            {
                "host": host,
                "scheme": schemes,
                "provider": provider,
                "ip": first_ip,
                "server": row.get("server", ""),
                "technologies": ", ".join(sorted(technologies)),
                "frameworks": ", ".join(sorted(frameworks)),
                "title": row.get("title", ""),
            }
        )

    return fingerprints


def detect_shadow_it(hosts, official_domains):
    rows = []
    for host in sorted(set(hosts)):
        is_shadow = not is_under_official_domain(host, official_domains)
        rows.append(
            {
                "asset": host,
                "is_shadow_it": "yes" if is_shadow else "no",
                "matched_official_domain": "" if is_shadow else next(
                    (
                        official
                        for official in official_domains
                        if host == official or host.endswith(f".{official}")
                    ),
                    "",
                ),
            }
        )
    return rows


def compute_risk_scores(web_rows, ssl_rows, shadow_rows, asn_rows, dns_records=None):
    ssl_by_host = {row["host"]: row for row in ssl_rows}
    shadow_by_host = {row["asset"]: row for row in shadow_rows}

    asn_known = {row.get("ip"): bool(row.get("org")) for row in asn_rows}
    risk_rows = []

    grouped_by_host = defaultdict(list)
    for row in web_rows:
        grouped_by_host[row["host"]].append(row)

    for host, host_rows in grouped_by_host.items():
        score = 0
        reasons = []

        shadow_flag = shadow_by_host.get(host, {}).get("is_shadow_it") == "yes"
        if shadow_flag:
            score += 30
            reasons.append("shadow-it-asset")

        http_ok = any(
            row["scheme"] == "http" and not row.get("error") and str(row.get("status", "")).isdigit() for row in host_rows
        )
        if http_ok:
            score += 10
            reasons.append("http-exposed")

        https_row = next((row for row in host_rows if row["scheme"] == "https"), None)
        if https_row:
            missing_headers = sum(1 for h in SEC_HEADERS if https_row.get(h, "") in ("", "MISSING"))
            if missing_headers >= 3:
                score += 10
                reasons.append("missing-security-headers")

        ssl_info = ssl_by_host.get(host)
        if not ssl_info or not ssl_info.get("ssl_ok"):
            score += 20
            reasons.append("no-valid-ssl")
        else:
            days_left = ssl_info.get("days_left")
            if isinstance(days_left, int) and days_left < 0:
                score += 20
                reasons.append("expired-certificate")
            elif isinstance(days_left, int) and days_left <= 30:
                score += 15
                reasons.append("certificate-expiring-soon")

        host_ips = []
        if dns_records:
            host_ips = dns_records.get(host, {}).get("A", [])

        if host_ips:
            has_known_provider = any(asn_known.get(ip, False) for ip in host_ips)
            if not has_known_provider:
                score += 10
                reasons.append("unknown-provider")
        elif dns_records:
            score += 5
            reasons.append("no-resolved-ip")
        elif not any(asn_known.values()):
            score += 10
            reasons.append("unknown-provider")

        if score >= 70:
            level = "critical"
        elif score >= 45:
            level = "high"
        elif score >= 25:
            level = "medium"
        else:
            level = "low"

        risk_rows.append(
            {
                "asset": host,
                "risk_score": score,
                "risk_level": level,
                "reasons": ", ".join(sorted(set(reasons))),
            }
        )

    risk_rows.sort(key=lambda x: x["risk_score"], reverse=True)
    return risk_rows
