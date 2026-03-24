import argparse
import contextlib
import csv
import html
import io
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

import complete


ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = ROOT / "results"
_MODULES = None

if load_dotenv:
    load_dotenv(ROOT / ".env")


class BridgeError(Exception):
    pass


def read_payload():
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BridgeError(f"Ongeldige JSON payload: {exc}") from exc


def parse_lines(value):
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = str(value).splitlines()
    cleaned = []
    for item in items:
        text = str(item).strip()
        if text:
            cleaned.append(text)
    return cleaned


def get_modules():
    global _MODULES
    if _MODULES is None:
        _MODULES = {
            "domain": complete.load_module("domain_module", ROOT / "domain" / "domain.py"),
            "dns": complete.load_module("dns_module", ROOT / "dns" / "dnsScan.py"),
            "whois": complete.load_module("whois_module", ROOT / "whoIs" / "script.py"),
        }
    return _MODULES


def ensure_run_dir(domain=None, run_id=None):
    if run_id:
        run_dir = (RESULTS_ROOT / run_id).resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    slug = complete.sanitize_slug(domain or "manual_scan")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = (RESULTS_ROOT / f"{slug}_{timestamp}").resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def build_intelx_dashboard_html(output_file, summary, records):
        def esc(value):
                return html.escape(str(value if value is not None else ""))

        generated_at = summary.get("generated_at", "")
        term = summary.get("term", "")
        days = summary.get("days", "")
        result_count = int(summary.get("result_count", 0) or 0)

        source_counts = {}
        for record in records:
                source_value = str(record.get("systemid") or record.get("bucket") or "unknown").strip() or "unknown"
                source_counts[source_value] = source_counts.get(source_value, 0) + 1

        top_sources = sorted(source_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        top_sources_html = "".join(
                f"<tr><td>{esc(name)}</td><td>{esc(count)}</td></tr>" for name, count in top_sources
        )

        preview_rows = []
        for record in records[:50]:
                preview_rows.append(
                        {
                                "name": record.get("name") or record.get("storageid") or "",
                                "date": record.get("date") or record.get("added") or "",
                                "type": record.get("type") or "",
                                "bucket": record.get("bucket") or "",
                                "systemid": record.get("systemid") or "",
                        }
                )

        rows_html = "".join(
                "<tr>"
                f"<td>{esc(row['name'])}</td>"
                f"<td>{esc(row['date'])}</td>"
                f"<td>{esc(row['type'])}</td>"
                f"<td>{esc(row['bucket'])}</td>"
                f"<td>{esc(row['systemid'])}</td>"
                "</tr>"
                for row in preview_rows
        )

        page_html = f"""
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>IntelX Credential Exposure Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #1f2937; background: #f8fafc; }}
        .section {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; margin-bottom: 14px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 10px; margin-top: 10px; }}
        .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; background: #f9fafb; }}
        .kpi {{ font-size: 22px; font-weight: 700; margin-top: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 7px; text-align: left; vertical-align: top; }}
        th {{ background: #f1f5f9; }}
        .muted {{ color: #64748b; }}
    </style>
</head>
<body>
    <h1>IntelX Credential Exposure Dashboard</h1>
    <p class=\"muted\">Generated at: {esc(generated_at)}</p>

    <div class=\"section\">
        <h2>Summary</h2>
        <div class=\"grid\">
            <div class=\"card\"><div>Search term</div><div class=\"kpi\">{esc(term)}</div></div>
            <div class=\"card\"><div>Lookback</div><div class=\"kpi\">{esc(days)} days</div></div>
            <div class=\"card\"><div>Matches</div><div class=\"kpi\">{esc(result_count)}</div></div>
            <div class=\"card\"><div>Preview rows</div><div class=\"kpi\">{esc(len(preview_rows))}</div></div>
        </div>
    </div>

    <div class=\"section\">
        <h2>Top Sources</h2>
        <table>
            <thead><tr><th>Source</th><th>Count</th></tr></thead>
            <tbody>{top_sources_html or '<tr><td colspan="2">No source data available.</td></tr>'}</tbody>
        </table>
    </div>

    <div class=\"section\">
        <h2>Result Preview (max 50)</h2>
        <table>
            <thead><tr><th>Name/Storage ID</th><th>Date</th><th>Type</th><th>Bucket</th><th>System ID</th></tr></thead>
            <tbody>{rows_html or '<tr><td colspan="5">No results found for this scan.</td></tr>'}</tbody>
        </table>
    </div>
</body>
</html>
"""
        output_file.write_text(page_html, encoding="utf-8")


def read_csv_rows(path):
    if not path or not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_text_input(run_dir, domain, hosts, prefix="subdomains"):
    file_path = run_dir / f"{prefix}_{complete.sanitize_slug(domain or 'manual')}.txt"
    file_path.write_text("\n".join(sorted(set(hosts))), encoding="utf-8")
    return file_path


def latest_matching_file(run_dir, pattern):
    matches = sorted(run_dir.glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def load_hosts_from_run(run_dir):
    host_file = latest_matching_file(run_dir, "subdomains_*.txt")
    if not host_file:
        raise BridgeError("Geen subdomain inputbestand gevonden voor deze run.")
    return parse_lines(host_file.read_text(encoding="utf-8")), host_file


def load_dns_records_from_run(run_dir):
    dns_csv = latest_matching_file(run_dir, "dns_scan_*.csv")
    if not dns_csv:
        raise BridgeError("Geen DNS CSV gevonden voor deze run.")
    return complete.parse_dns_csv(dns_csv), dns_csv


def get_summary(run_dir):
    summary_path = run_dir / "summary.json"
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def list_files(run_dir):
    files = []
    for file_path in sorted(run_dir.iterdir()):
        if file_path.is_file():
            files.append(
                {
                    "name": file_path.name,
                    "relativePath": f"results/{run_dir.name}/{file_path.name}",
                    "size": file_path.stat().st_size,
                }
            )
    return files


def result_payload(action, run_dir, **extra):
    return {
        "ok": True,
        "action": action,
        "runId": run_dir.name,
        "runDir": str(run_dir),
        "summary": get_summary(run_dir),
        "files": list_files(run_dir),
        **extra,
    }


def write_whois_csv(run_dir, whois_data, related_domains):
    rows = [
        {
            "domain": whois_data.get("domain", ""),
            "emails": "; ".join(whois_data.get("emails", [])),
            "org": whois_data.get("org", ""),
            "name": whois_data.get("name", ""),
            "registrar": whois_data.get("registrar", ""),
            "nameservers": "; ".join(whois_data.get("nameservers", [])),
            "related_domains": "; ".join(related_domains),
        }
    ]
    complete.write_csv(
        run_dir / "whois_related.csv",
        rows,
        ["domain", "emails", "org", "name", "registrar", "nameservers", "related_domains"],
    )


def action_whois(payload):
    domain = str(payload.get("domain", "")).strip().lower()
    if not domain:
        raise BridgeError("`domain` is verplicht voor WHOIS.")

    run_dir = ensure_run_dir(domain, payload.get("runId"))
    modules = get_modules()
    with contextlib.redirect_stdout(sys.stderr):
        whois_data = complete.run_whois_discovery(modules["whois"], domain)
    related_domains = whois_data.get("related_domains", [])
    write_whois_csv(run_dir, whois_data, related_domains)

    return result_payload(
        "whois",
        run_dir,
        whois=whois_data,
        relatedDomains=related_domains,
        previewRows=read_csv_rows(run_dir / "whois_related.csv")[:10],
    )


def action_ct(payload):
    domain = str(payload.get("domain", "")).strip().lower()
    if not domain:
        raise BridgeError("`domain` is verplicht voor CT discovery.")

    run_dir = ensure_run_dir(domain, payload.get("runId"))
    modules = get_modules()

    related_domains = parse_lines(payload.get("relatedDomainsText"))
    if not related_domains:
        with contextlib.redirect_stdout(sys.stderr):
            whois_data = complete.run_whois_discovery(modules["whois"], domain)
        max_related = int(payload.get("maxRelatedDomains", 10) or 10)
        related_domains = whois_data.get("related_domains", [])[: max(0, max_related)]
        write_whois_csv(run_dir, whois_data, related_domains)

    source_domains = [domain] + [item.lower() for item in related_domains]
    with contextlib.redirect_stdout(sys.stderr):
        ct_rows, ct_subdomains, ct_source_logs = complete.collect_ct_data(modules["domain"], source_domains)
    complete.write_csv(run_dir / "ct_log_discovery.csv", ct_rows, ["source_domain", "discovered_name", "source"])
    complete.write_csv(
        run_dir / "ct_source_status.csv",
        ct_source_logs,
        ["source_domain", "source", "status", "items", "error"],
    )
    write_text_input(run_dir, domain, ct_subdomains, prefix="subdomains")

    return result_payload(
        "ct-discovery",
        run_dir,
        sourceDomains=source_domains,
        subdomains=ct_subdomains,
        previewRows=ct_rows[:20],
    )


def action_enumeration(payload):
    domain = str(payload.get("domain", "")).strip().lower()
    if not domain:
        raise BridgeError("`domain` is verplicht voor subdomain enumeration.")

    run_dir = ensure_run_dir(domain, payload.get("runId"))
    with contextlib.redirect_stdout(sys.stderr):
        external_subs, tool_logs = complete.run_external_subdomain_tools(domain)
    additional_hosts = [host.lower() for host in parse_lines(payload.get("additionalSubdomainsText"))]
    all_hosts = sorted(set(external_subs) | set(additional_hosts) | {domain})
    complete.write_csv(run_dir / "enumeration_tools.csv", tool_logs, ["tool", "return_code", "items", "error"])
    sub_file = write_text_input(run_dir, domain, all_hosts, prefix="subdomains")

    return result_payload(
        "subdomain-enumeration",
        run_dir,
        subdomains=all_hosts,
        subdomainFile=sub_file.name,
        toolLogs=tool_logs,
    )


def action_dns(payload):
    domain = str(payload.get("domain", "manual")).strip().lower() or "manual"
    hosts = [host.lower() for host in parse_lines(payload.get("subdomainsText"))]
    run_dir = ensure_run_dir(domain, payload.get("runId"))

    if not hosts:
        hosts, _ = load_hosts_from_run(run_dir)

    if not hosts:
        raise BridgeError("Geen subdomeinen opgegeven voor DNS scan.")

    modules = get_modules()
    sub_file = write_text_input(run_dir, domain, hosts, prefix="subdomains")
    with contextlib.redirect_stdout(sys.stderr):
        dns_csv, scanned_count, with_records_count = modules["dns"].run(sub_file, run_dir)

    dns_records = complete.parse_dns_csv(dns_csv)
    ip_set = set()
    for records in dns_records.values():
        for ip in records.get("A", []):
            ip_set.add(ip)

    existing_summary = get_summary(run_dir)
    summary = {
        "generated_at": datetime.now().isoformat(),
        "domain": domain,
        "subdomains_count": len(sorted(set(hosts))),
        "resolved_hosts_count": with_records_count,
        "ips_count": len(ip_set),
        "high_or_critical_risk_count": sum(
            1 for row in read_csv_rows(run_dir / "risk_scores.csv") if row.get("risk_level") in ("high", "critical")
        ),
        "scanned_count": scanned_count,
    }
    write_json(run_dir / "summary.json", {**existing_summary, **summary})

    complete.build_dashboard_html(
        run_dir / "dashboard.html",
        get_summary(run_dir),
        {
            "risk_rows": read_csv_rows(run_dir / "risk_scores.csv"),
            "shadow_rows": read_csv_rows(run_dir / "shadow_it.csv"),
            "ssl_rows": read_csv_rows(run_dir / "ssl_scan.csv"),
            "web_rows": read_csv_rows(run_dir / "web_scan_assets.csv"),
            "ct_rows": read_csv_rows(run_dir / "ct_log_discovery.csv"),
            "asn_rows": read_csv_rows(run_dir / "asn_lookup.csv"),
            "reverse_ip_rows": read_csv_rows(run_dir / "reverse_ip_clusters.csv"),
            "fingerprint_rows": read_csv_rows(run_dir / "fingerprinting.csv"),
            "email_security_rows": read_csv_rows(run_dir / "email_security.csv"),
            "takeover_rows": read_csv_rows(run_dir / "subdomain_takeover_candidates.csv"),
            "cloud_rows": read_csv_rows(run_dir / "cloud_misconfigurations.csv"),
            "passive_vuln_rows": read_csv_rows(run_dir / "vulnerability_passive.csv"),
            "whois_data": {},
            "tool_logs": read_csv_rows(run_dir / "enumeration_tools.csv"),
        },
    )

    return result_payload(
        "dns-resolution",
        run_dir,
        scannedCount=scanned_count,
        withRecordsCount=with_records_count,
        previewRows=read_csv_rows(dns_csv)[:20],
    )


def action_reverse_ip(payload):
    run_dir = ensure_run_dir(payload.get("domain") or "manual", payload.get("runId"))
    dns_csv_text = str(payload.get("dnsCsvText", "")).strip()

    if dns_csv_text:
        temp_dns = run_dir / "dns_manual_input.csv"
        temp_dns.write_text(dns_csv_text, encoding="utf-8")
        dns_records = complete.parse_dns_csv(temp_dns)
    else:
        dns_records, _ = load_dns_records_from_run(run_dir)

    reverse_ip_rows, ip_list = complete.build_reverse_ip_clusters(dns_records)
    complete.write_csv(
        run_dir / "reverse_ip_clusters.csv",
        reverse_ip_rows,
        ["ip", "local_hosts_count", "local_hosts", "external_hosts_count", "external_hosts"],
    )

    return result_payload(
        "reverse-ip",
        run_dir,
        ips=ip_list,
        previewRows=reverse_ip_rows[:20],
    )


def action_asn(payload):
    run_dir = ensure_run_dir(payload.get("domain") or "manual", payload.get("runId"))
    ip_list = parse_lines(payload.get("ipsText"))
    ipinfo_token = str(payload.get("ipinfoToken", "")).strip()

    if not ip_list:
        dns_records, _ = load_dns_records_from_run(run_dir)
        found_ips = set()
        for records in dns_records.values():
            for ip in records.get("A", []):
                found_ips.add(ip)
        ip_list = sorted(found_ips)

    if not ip_list:
        raise BridgeError("Geen IP-adressen beschikbaar voor ASN lookup.")

    asn_rows = []
    for ip in ip_list:
        row = complete.lookup_asn_ipinfo(ip, token=ipinfo_token)
        asn_rows.append(row or {"ip": ip, "asn": "", "org": "", "hostname": "", "city": "", "region": "", "country": ""})

    complete.write_csv(run_dir / "asn_lookup.csv", asn_rows, ["ip", "asn", "org", "hostname", "city", "region", "country"])
    return result_payload("asn-lookup", run_dir, previewRows=asn_rows[:20])


def action_web(payload):
    domain = str(payload.get("domain", "manual")).strip().lower() or "manual"
    run_dir = ensure_run_dir(domain, payload.get("runId"))
    hosts = [host.lower() for host in parse_lines(payload.get("hostsText"))]

    if not hosts:
        hosts, _ = load_hosts_from_run(run_dir)

    if not hosts:
        raise BridgeError("Geen hosts beschikbaar voor web scan.")

    web_rows = []
    for host in sorted(set(hosts)):
        web_rows.append(complete.scan_web_asset(host, "http"))
        web_rows.append(complete.scan_web_asset(host, "https"))

    complete.write_csv(
        run_dir / "web_scan_assets.csv",
        web_rows,
        ["host", "url", "scheme", "status", "final_url", "server", "x_powered_by", "generator", "title", "error"] + complete.SEC_HEADERS,
    )
    return result_payload("web-scan", run_dir, previewRows=web_rows[:20])


def action_ssl(payload):
    domain = str(payload.get("domain", "manual")).strip().lower() or "manual"
    run_dir = ensure_run_dir(domain, payload.get("runId"))
    hosts = [host.lower() for host in parse_lines(payload.get("hostsText"))]

    if not hosts:
        hosts, _ = load_hosts_from_run(run_dir)

    if not hosts:
        raise BridgeError("Geen hosts beschikbaar voor SSL scan.")

    ssl_rows = [complete.ssl_scan_host(host) for host in sorted(set(hosts))]
    complete.write_csv(
        run_dir / "ssl_scan.csv",
        ssl_rows,
        ["host", "ssl_ok", "issuer", "subject", "serial_number", "not_before", "not_after", "days_left", "error"],
    )
    return result_payload("ssl-scan", run_dir, previewRows=ssl_rows[:20])


def action_fingerprint(payload):
    run_id = payload.get("runId")
    if not run_id:
        raise BridgeError("`runId` is verplicht voor fingerprinting.")

    run_dir = ensure_run_dir(payload.get("domain") or "manual", run_id)
    dns_records, _ = load_dns_records_from_run(run_dir)
    web_rows = read_csv_rows(run_dir / "web_scan_assets.csv")
    asn_rows = read_csv_rows(run_dir / "asn_lookup.csv")
    ssl_rows = read_csv_rows(run_dir / "ssl_scan.csv")

    if not web_rows or not ssl_rows:
        raise BridgeError("Fingerprinting vereist web_scan_assets.csv en ssl_scan.csv in de run-map.")

    fingerprint_rows = complete.fingerprint_assets(web_rows, asn_rows, dns_records, ssl_rows)
    complete.write_csv(
        run_dir / "fingerprinting.csv",
        fingerprint_rows,
        ["host", "scheme", "provider", "ip", "server", "technologies", "frameworks", "title"],
    )
    return result_payload("fingerprint", run_dir, previewRows=fingerprint_rows[:20])


def action_shadow(payload):
    domain = str(payload.get("domain", "")).strip().lower()
    run_dir = ensure_run_dir(domain or "manual", payload.get("runId"))
    hosts = [host.lower() for host in parse_lines(payload.get("hostsText"))]

    if not hosts:
        hosts, _ = load_hosts_from_run(run_dir)

    if not domain:
        summary = get_summary(run_dir)
        domain = str(summary.get("domain", "")).strip().lower()

    if not domain:
        raise BridgeError("`domain` is verplicht voor Shadow IT detection.")

    official_domains_file = None
    official_domains_text = str(payload.get("officialDomainsText", "")).strip()
    if official_domains_text:
        official_domains_file = run_dir / "official_domains.txt"
        official_domains_file.write_text(official_domains_text, encoding="utf-8")

    official_domains = complete.read_official_domains(domain, official_domains_file)
    shadow_rows = complete.detect_shadow_it(hosts, official_domains)
    complete.write_csv(run_dir / "shadow_it.csv", shadow_rows, ["asset", "is_shadow_it", "matched_official_domain"])
    return result_payload("shadow-it", run_dir, previewRows=shadow_rows[:20], officialDomains=official_domains)


def action_risk(payload):
    run_id = payload.get("runId")
    if not run_id:
        raise BridgeError("`runId` is verplicht voor risk scoring.")

    domain = str(payload.get("domain", "")).strip().lower()
    run_dir = ensure_run_dir(payload.get("domain") or "manual", run_id)
    web_rows = read_csv_rows(run_dir / "web_scan_assets.csv")
    ssl_rows = read_csv_rows(run_dir / "ssl_scan.csv")
    shadow_rows = read_csv_rows(run_dir / "shadow_it.csv")
    asn_rows = read_csv_rows(run_dir / "asn_lookup.csv")
    dns_records, _ = load_dns_records_from_run(run_dir)

    if not domain:
        summary = get_summary(run_dir)
        domain = str(summary.get("domain", "")).strip().lower()

    if not web_rows or not ssl_rows or not shadow_rows:
        raise BridgeError("Risk scoring vereist web_scan_assets.csv, ssl_scan.csv en shadow_it.csv.")
    if not domain:
        raise BridgeError("`domain` ontbreekt voor email security checks binnen risk scoring.")

    risk_rows = complete.compute_risk_scores(web_rows, ssl_rows, shadow_rows, asn_rows, dns_records=dns_records)
    complete.write_csv(run_dir / "risk_scores.csv", risk_rows, ["asset", "risk_score", "risk_level", "reasons"])

    email_security_rows = complete.evaluate_email_security(domain)
    complete.write_csv(
        run_dir / "email_security.csv",
        email_security_rows,
        ["domain", "mx_count", "mx_records", "spf_mode", "spf_record", "dmarc_policy", "dmarc_record", "dkim_status", "dkim_selectors", "dkim_records", "mta_sts", "tls_rpt", "risk_level", "issues"],
    )

    takeover_rows = complete.detect_subdomain_takeover_risks(dns_records, web_rows)
    complete.write_csv(
        run_dir / "subdomain_takeover_candidates.csv",
        takeover_rows,
        ["host", "cname", "provider", "finding", "severity", "confidence", "recommendation"],
    )

    cloud_rows = complete.detect_cloud_misconfigurations(dns_records, web_rows)
    complete.write_csv(
        run_dir / "cloud_misconfigurations.csv",
        cloud_rows,
        ["asset", "provider", "check", "severity", "status", "evidence", "recommendation"],
    )

    passive_vuln_rows = complete.compute_passive_vulnerability_indicators(web_rows, ssl_rows)
    complete.write_csv(
        run_dir / "vulnerability_passive.csv",
        passive_vuln_rows,
        ["host", "category", "severity", "indicator", "evidence", "recommendation"],
    )
    return result_payload("risk-score", run_dir, previewRows=risk_rows[:20])


def action_full_scan(payload):
    domain = str(payload.get("domain", "")).strip().lower()
    if not domain:
        raise BridgeError("`domain` is verplicht voor een volledige scan.")

    run_dir = ensure_run_dir(domain, payload.get("runId"))
    modules = get_modules()

    official_domains_file = None
    official_domains_text = str(payload.get("officialDomainsText", "")).strip()
    if official_domains_text:
        official_domains_file = run_dir / "official_domains.txt"
        official_domains_file.write_text(official_domains_text, encoding="utf-8")

    ipinfo_token = str(payload.get("ipinfoToken", "")).strip()
    max_related_domains = int(payload.get("maxRelatedDomains", 10) or 10)

    with contextlib.redirect_stdout(sys.stderr):
        whois_data = complete.run_whois_discovery(modules["whois"], domain)
    related_domains = whois_data["related_domains"][: max(0, max_related_domains)]
    write_whois_csv(run_dir, whois_data, related_domains)

    ct_domains = [domain] + related_domains
    with contextlib.redirect_stdout(sys.stderr):
        ct_rows, ct_subdomains, ct_source_logs = complete.collect_ct_data(modules["domain"], ct_domains)
    complete.write_csv(run_dir / "ct_log_discovery.csv", ct_rows, ["source_domain", "discovered_name", "source"])
    complete.write_csv(
        run_dir / "ct_source_status.csv",
        ct_source_logs,
        ["source_domain", "source", "status", "items", "error"],
    )

    with contextlib.redirect_stdout(sys.stderr):
        external_subs, tool_logs = complete.run_external_subdomain_tools(domain)
    complete.write_csv(run_dir / "enumeration_tools.csv", tool_logs, ["tool", "return_code", "items", "error"])

    all_subdomains = sorted(set(ct_subdomains) | set(external_subs) | {domain})
    sub_file = write_text_input(run_dir, domain, all_subdomains, prefix="subdomains")

    with contextlib.redirect_stdout(sys.stderr):
        dns_csv, scanned_count, with_records_count = modules["dns"].run(sub_file, run_dir)
    dns_records = complete.parse_dns_csv(dns_csv)

    reverse_ip_rows, ip_list = complete.build_reverse_ip_clusters(dns_records)
    complete.write_csv(
        run_dir / "reverse_ip_clusters.csv",
        reverse_ip_rows,
        ["ip", "local_hosts_count", "local_hosts", "external_hosts_count", "external_hosts"],
    )

    asn_rows = []
    for ip in ip_list:
        row = complete.lookup_asn_ipinfo(ip, token=ipinfo_token)
        asn_rows.append(row or {"ip": ip, "asn": "", "org": "", "hostname": "", "city": "", "region": "", "country": ""})
    complete.write_csv(run_dir / "asn_lookup.csv", asn_rows, ["ip", "asn", "org", "hostname", "city", "region", "country"])

    web_rows = []
    for host in all_subdomains:
        web_rows.append(complete.scan_web_asset(host, "http"))
        web_rows.append(complete.scan_web_asset(host, "https"))
    complete.write_csv(
        run_dir / "web_scan_assets.csv",
        web_rows,
        ["host", "url", "scheme", "status", "final_url", "server", "x_powered_by", "generator", "title", "error"] + complete.SEC_HEADERS,
    )

    ssl_rows = [complete.ssl_scan_host(host) for host in all_subdomains]
    complete.write_csv(
        run_dir / "ssl_scan.csv",
        ssl_rows,
        ["host", "ssl_ok", "issuer", "subject", "serial_number", "not_before", "not_after", "days_left", "error"],
    )

    fingerprint_rows = complete.fingerprint_assets(web_rows, asn_rows, dns_records, ssl_rows)
    complete.write_csv(
        run_dir / "fingerprinting.csv",
        fingerprint_rows,
        ["host", "scheme", "provider", "ip", "server", "technologies", "frameworks", "title"],
    )

    official_domains = complete.read_official_domains(domain, official_domains_file)
    shadow_rows = complete.detect_shadow_it(all_subdomains, official_domains)
    complete.write_csv(run_dir / "shadow_it.csv", shadow_rows, ["asset", "is_shadow_it", "matched_official_domain"])

    risk_rows = complete.compute_risk_scores(web_rows, ssl_rows, shadow_rows, asn_rows, dns_records=dns_records)
    complete.write_csv(run_dir / "risk_scores.csv", risk_rows, ["asset", "risk_score", "risk_level", "reasons"])

    email_security_rows = complete.evaluate_email_security(domain)
    complete.write_csv(
        run_dir / "email_security.csv",
        email_security_rows,
        ["domain", "mx_count", "mx_records", "spf_mode", "spf_record", "dmarc_policy", "dmarc_record", "dkim_status", "dkim_selectors", "dkim_records", "mta_sts", "tls_rpt", "risk_level", "issues"],
    )

    takeover_rows = complete.detect_subdomain_takeover_risks(dns_records, web_rows)
    complete.write_csv(
        run_dir / "subdomain_takeover_candidates.csv",
        takeover_rows,
        ["host", "cname", "provider", "finding", "severity", "confidence", "recommendation"],
    )

    cloud_rows = complete.detect_cloud_misconfigurations(dns_records, web_rows)
    complete.write_csv(
        run_dir / "cloud_misconfigurations.csv",
        cloud_rows,
        ["asset", "provider", "check", "severity", "status", "evidence", "recommendation"],
    )

    passive_vuln_rows = complete.compute_passive_vulnerability_indicators(web_rows, ssl_rows)
    complete.write_csv(
        run_dir / "vulnerability_passive.csv",
        passive_vuln_rows,
        ["host", "category", "severity", "indicator", "evidence", "recommendation"],
    )

    summary = {
        "generated_at": datetime.now().isoformat(),
        "domain": domain,
        "related_domains_count": len(related_domains),
        "subdomains_count": len(all_subdomains),
        "resolved_hosts_count": with_records_count,
        "ips_count": len(ip_list),
        "shadow_assets_count": sum(1 for row in shadow_rows if row["is_shadow_it"] == "yes"),
        "high_or_critical_risk_count": sum(1 for row in risk_rows if row["risk_level"] in ("high", "critical")),
        "takeover_candidates_count": len(takeover_rows),
        "cloud_misconfig_count": len(cloud_rows),
        "email_security_high_risk_count": sum(1 for row in email_security_rows if row["risk_level"] == "high"),
        "passive_vuln_high_count": sum(1 for row in passive_vuln_rows if row["severity"] == "high"),
        "scanned_count": scanned_count,
    }
    write_json(run_dir / "summary.json", summary)
    complete.build_dashboard_html(
        run_dir / "dashboard.html",
        summary,
        {
            "risk_rows": risk_rows,
            "shadow_rows": shadow_rows,
            "ssl_rows": ssl_rows,
            "web_rows": web_rows,
            "ct_rows": ct_rows,
            "asn_rows": asn_rows,
            "reverse_ip_rows": reverse_ip_rows,
            "fingerprint_rows": fingerprint_rows,
            "email_security_rows": email_security_rows,
            "takeover_rows": takeover_rows,
            "cloud_rows": cloud_rows,
            "passive_vuln_rows": passive_vuln_rows,
            "whois_data": whois_data,
            "tool_logs": tool_logs,
        },
    )

    return result_payload(
        "full-scan",
        run_dir,
        summary=summary,
        preview={
            "riskRows": risk_rows[:10],
            "shadowRows": shadow_rows[:10],
            "subdomains": all_subdomains[:50],
        },
    )


def action_intelx(payload):
    import intelx as intelx_module

    term = str(payload.get("term", "")).strip()
    if not term:
        raise BridgeError("`term` is verplicht voor IntelX search (domein of e-mail).")

    if not intelx_module.API_KEY:
        raise BridgeError("INTELX_API_KEY is niet ingesteld in .env.")

    days = int(payload.get("days", 7) or 7)
    limit = int(payload.get("limit", 100) or 100)

    slug = complete.sanitize_slug(term.replace("@", "_at_"))
    run_dir = ensure_run_dir(slug, payload.get("runId"))

    with contextlib.redirect_stdout(sys.stderr):
        records = intelx_module.search_one(term, maxresults=limit, limit=limit, cutoff_days=days)

    split_rows: list = []
    split_keys: set = set()
    intelx_module.collect_records(term, records, split_rows, split_keys)

    if split_rows:
        out_path = run_dir / "intelx_results.csv"
        intelx_module.write_split_csv(split_rows, split_keys, out_path)

    out_raw = run_dir / "intelx_raw.csv"
    import csv as _csv
    import json as _json
    with out_raw.open("w", encoding="utf-8", newline="") as fh:
        writer = _csv.writer(fh)
        writer.writerow(["term", "result_count", "records_json"])
        writer.writerow([term, len(records), _json.dumps(records, ensure_ascii=False)])

    summary = {
        "generated_at": datetime.now().isoformat(),
        "action": "intelx-search",
        "term": term,
        "days": days,
        "result_count": len(records),
    }
    write_json(run_dir / "summary.json", summary)
    build_intelx_dashboard_html(run_dir / "dashboard.html", summary, records)

    return result_payload(
        "intelx-search",
        run_dir,
        term=term,
        resultCount=len(records),
        days=days,
        previewRows=split_rows[:20],
    )


def action_port_scan(payload):
    """
    Active port scanning using Nmap.
    WARNING: This may trigger SIEM/IDS alerts. Use with authorization only.
    """
    import port_scan as ps

    target = str(payload.get("target", "")).strip()
    if not target:
        raise BridgeError("`target` is verplicht voor port scan (hostname of IP).")

    scan_type = str(payload.get("scanType", "sS")).strip()
    ports_spec = str(payload.get("portsSpec", "--top-ports 1000")).strip()
    extra_args = str(payload.get("extraArgs", "")).strip()

    slug = complete.sanitize_slug(target)
    run_dir = ensure_run_dir(slug, payload.get("runId"))

    try:
        with contextlib.redirect_stdout(sys.stderr):
            result = ps.perform_port_scan(target, scan_type=scan_type, ports=ports_spec, extra_args=extra_args)
    except Exception as exc:
        error_summary = {
            "generated_at": datetime.now().isoformat(),
            "action": "port-scan",
            "target": target,
            "scan_type": scan_type,
            "ports_spec": ports_spec,
            "status": "failed",
            "error": str(exc),
        }
        write_json(run_dir / "summary.json", error_summary)
        raise BridgeError(f"Port scan mislukt: {exc}") from exc

    # Write detailed results
    out_csv = run_dir / "port_scan_results.csv"
    if result.get("all_ports"):
        complete.write_csv(
            out_csv,
            result["all_ports"],
            ["host", "port", "protocol", "state", "service"],
        )

    summary = {
        "generated_at": datetime.now().isoformat(),
        "action": "port-scan",
        "target": target,
        "scan_type": scan_type,
        "ports_spec": ports_spec,
        "open_count": len(result.get("open_ports", [])),
        "filtered_count": len(result.get("filtered_ports", [])),
        "closed_count": len(result.get("closed_ports", [])),
    }
    write_json(run_dir / "summary.json", summary)

    preview_rows = result.get("all_ports", [])[:30]
    return result_payload(
        "port-scan",
        run_dir,
        target=target,
        scanType=scan_type,
        openCount=len(result.get("open_ports", [])),
        filteredCount=len(result.get("filtered_ports", [])),
        closedCount=len(result.get("closed_ports", [])),
        previewRows=preview_rows,
    )


def action_screenshots(payload):
    """
    Optional manual screenshot capture using Playwright.
    Kept separate from full-scan to preserve zero-extra-tools baseline.
    """
    domain = str(payload.get("domain", "manual")).strip().lower() or "manual"
    run_dir = ensure_run_dir(domain, payload.get("runId"))
    hosts = [host.lower() for host in parse_lines(payload.get("hostsText"))]

    if not hosts:
        hosts, _ = load_hosts_from_run(run_dir)

    if not hosts:
        raise BridgeError("Geen hosts beschikbaar voor screenshot capture.")

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise BridgeError(
            "Playwright is niet beschikbaar. Installeer handmatig met `pip install playwright` en daarna `python -m playwright install chromium`."
        ) from exc

    screenshot_dir = run_dir / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for host in sorted(set(hosts)):
                captured = False
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    file_name = f"{complete.sanitize_slug(host)}_{scheme}.png"
                    output_path = screenshot_dir / file_name

                    page = browser.new_page(viewport={"width": 1366, "height": 768})
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=12000)
                        page.screenshot(path=str(output_path), full_page=True)
                        rows.append(
                            {
                                "host": host,
                                "url": url,
                                "status": "ok",
                                "file": f"results/{run_dir.name}/screenshots/{file_name}",
                                "error": "",
                            }
                        )
                        captured = True
                        break
                    except Exception as exc:
                        rows.append(
                            {
                                "host": host,
                                "url": url,
                                "status": "error",
                                "file": "",
                                "error": str(exc),
                            }
                        )
                    finally:
                        page.close()

                if not captured:
                    continue
        finally:
            browser.close()

    complete.write_csv(run_dir / "screenshots.csv", rows, ["host", "url", "status", "file", "error"])
    return result_payload("screenshots", run_dir, previewRows=rows[:30])


ACTIONS = {
    "whois": action_whois,
    "ct-discovery": action_ct,
    "subdomain-enumeration": action_enumeration,
    "dns-resolution": action_dns,
    "reverse-ip": action_reverse_ip,
    "asn-lookup": action_asn,
    "web-scan": action_web,
    "ssl-scan": action_ssl,
    "fingerprint": action_fingerprint,
    "shadow-it": action_shadow,
    "risk-score": action_risk,
    "full-scan": action_full_scan,
    "intelx-search": action_intelx,
    "port-scan": action_port_scan,
    "screenshots": action_screenshots,
}


def main():
    parser = argparse.ArgumentParser(description="Bridge script voor scan API")
    parser.add_argument("--action", required=True, choices=sorted(ACTIONS.keys()))
    args = parser.parse_args()

    try:
        payload = read_payload()
        response = ACTIONS[args.action](payload)
        print(json.dumps(response, ensure_ascii=False))
    except BridgeError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), end="")
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"Onverwachte fout: {exc}"}), end="")
        sys.exit(1)


if __name__ == "__main__":
    main()
