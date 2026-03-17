import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from discovery_pipeline.analysis.assets import compute_risk_scores, detect_shadow_it, fingerprint_assets
from discovery_pipeline.analysis.security import (
    compute_passive_vulnerability_indicators,
    detect_cloud_misconfigurations,
    detect_subdomain_takeover_risks,
    evaluate_email_security,
)
from discovery_pipeline.constants import SEC_HEADERS
from discovery_pipeline.core.utils import load_module, read_official_domains, sanitize_slug, write_csv
from discovery_pipeline.discovery.enumeration import run_external_subdomain_tools
from discovery_pipeline.discovery.whois_ct import collect_ct_data, run_whois_discovery
from discovery_pipeline.reporting.dashboard import build_dashboard_html
from discovery_pipeline.scanning.network import build_reverse_ip_clusters, lookup_asn_ipinfo, parse_dns_csv
from discovery_pipeline.scanning.web import scan_web_asset, ssl_scan_host


def parse_args():
    parser = argparse.ArgumentParser(description="Complete automated discovery pipeline")
    parser.add_argument("--domain", required=True, help="Root domain to scan")
    parser.add_argument("--results-dir", default="results", help="Base directory for scan outputs")
    parser.add_argument(
        "--official-domains-file",
        help="Optional txt file with official domains (one per line) for Shadow IT detection",
    )
    parser.add_argument("--ipinfo-token", default=os.getenv("IPINFO_TOKEN", ""), help="Optional ipinfo token")
    parser.add_argument("--max-related-domains", type=int, default=10, help="Limit related domains for CT lookups")
    return parser.parse_args()


def main():
    args = parse_args()
    root = Path(__file__).resolve().parents[1]

    domain_module = load_module("domain_module", root / "domain" / "domain.py")
    dns_module = load_module("dns_module", root / "dns" / "dnsScan.py")
    whois_module = load_module("whois_module", root / "whoIs" / "script.py")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = (root / args.results_dir / f"{sanitize_slug(args.domain)}_{timestamp}").resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/17] Input domain: {args.domain}")

    print("[2/17] WHOIS lookup + related domains")
    whois_data = run_whois_discovery(whois_module, args.domain.strip().lower())
    related_domains = whois_data["related_domains"][: max(0, args.max_related_domains)]

    whois_rows = [
        {
            "domain": whois_data["domain"],
            "emails": "; ".join(whois_data["emails"]),
            "org": whois_data["org"],
            "name": whois_data["name"],
            "registrar": whois_data["registrar"],
            "nameservers": "; ".join(whois_data["nameservers"]),
            "related_domains": "; ".join(related_domains),
        }
    ]
    write_csv(
        run_dir / "whois_related.csv",
        whois_rows,
        ["domain", "emails", "org", "name", "registrar", "nameservers", "related_domains"],
    )

    print("[3/17] CT logs (crt.sh)")
    ct_domains = [args.domain.strip().lower()] + related_domains
    ct_rows, ct_subdomains, ct_source_logs = collect_ct_data(domain_module, ct_domains)
    write_csv(run_dir / "ct_log_discovery.csv", ct_rows, ["source_domain", "discovered_name", "source"])
    write_csv(
        run_dir / "ct_source_status.csv",
        ct_source_logs,
        ["source_domain", "source", "status", "items", "error"],
    )

    print("[4/17] Subdomain enumeration")
    external_subs, tool_logs = run_external_subdomain_tools(args.domain.strip().lower())
    write_csv(run_dir / "enumeration_tools.csv", tool_logs, ["tool", "return_code", "items", "error"])
    all_subdomains = sorted(set(ct_subdomains) | set(external_subs) | {args.domain.strip().lower()})
    sub_file = run_dir / f"subdomains_{sanitize_slug(args.domain)}.txt"
    sub_file.write_text("\n".join(all_subdomains), encoding="utf-8")

    print("[5/17] DNS resolution")
    dns_csv, scanned_count, with_records_count = dns_module.run(sub_file, run_dir)
    dns_records = parse_dns_csv(dns_csv)

    print("[6/17] Reverse IP lookups")
    reverse_ip_rows, ip_list = build_reverse_ip_clusters(dns_records)
    write_csv(
        run_dir / "reverse_ip_clusters.csv",
        reverse_ip_rows,
        ["ip", "local_hosts_count", "local_hosts", "external_hosts_count", "external_hosts"],
    )

    print("[7/17] ASN lookup")
    asn_rows = []
    for ip in ip_list:
        row = lookup_asn_ipinfo(ip, token=args.ipinfo_token)
        if row:
            asn_rows.append(row)
        else:
            asn_rows.append({"ip": ip, "asn": "", "org": "", "hostname": "", "city": "", "region": "", "country": ""})
    write_csv(run_dir / "asn_lookup.csv", asn_rows, ["ip", "asn", "org", "hostname", "city", "region", "country"])

    print("[8/17] Web scan HTTP(S)")
    web_rows = []
    for host in all_subdomains:
        web_rows.append(scan_web_asset(host, "http"))
        web_rows.append(scan_web_asset(host, "https"))
    write_csv(
        run_dir / "web_scan_assets.csv",
        web_rows,
        ["host", "url", "scheme", "status", "final_url", "server", "x_powered_by", "generator", "title", "error"] + SEC_HEADERS,
    )

    print("[9/17] SSL scan HTTPS assets")
    ssl_rows = [ssl_scan_host(host) for host in all_subdomains]
    write_csv(
        run_dir / "ssl_scan.csv",
        ssl_rows,
        ["host", "ssl_ok", "issuer", "subject", "serial_number", "not_before", "not_after", "days_left", "error"],
    )

    print("[10/17] Fingerprinting")
    fingerprint_rows = fingerprint_assets(web_rows, asn_rows, dns_records, ssl_rows)
    write_csv(
        run_dir / "fingerprinting.csv",
        fingerprint_rows,
        ["host", "scheme", "provider", "ip", "server", "technologies", "frameworks", "title"],
    )

    print("[11/17] Shadow IT detection")
    official_domains = read_official_domains(
        args.domain.strip().lower(),
        Path(args.official_domains_file) if args.official_domains_file else None,
    )
    shadow_rows = detect_shadow_it(all_subdomains, official_domains)
    write_csv(run_dir / "shadow_it.csv", shadow_rows, ["asset", "is_shadow_it", "matched_official_domain"])

    print("[12/17] Risk scoring")
    risk_rows = compute_risk_scores(web_rows, ssl_rows, shadow_rows, asn_rows, dns_records=dns_records)
    write_csv(run_dir / "risk_scores.csv", risk_rows, ["asset", "risk_score", "risk_level", "reasons"])

    print("[13/17] Email security checks (passive)")
    email_security_rows = evaluate_email_security(args.domain.strip().lower())
    write_csv(
        run_dir / "email_security.csv",
        email_security_rows,
        ["domain", "mx_count", "mx_records", "spf_mode", "spf_record", "dmarc_policy", "dmarc_record", "dkim_status", "dkim_selectors", "dkim_records", "mta_sts", "tls_rpt", "risk_level", "issues"],
    )

    print("[14/17] Subdomain takeover detection (passive)")
    takeover_rows = detect_subdomain_takeover_risks(dns_records, web_rows)
    write_csv(
        run_dir / "subdomain_takeover_candidates.csv",
        takeover_rows,
        ["host", "cname", "provider", "finding", "severity", "confidence", "recommendation"],
    )

    print("[15/17] Cloud misconfiguration checks (passive)")
    cloud_rows = detect_cloud_misconfigurations(dns_records, web_rows)
    write_csv(
        run_dir / "cloud_misconfigurations.csv",
        cloud_rows,
        ["asset", "provider", "check", "severity", "status", "evidence", "recommendation"],
    )

    print("[16/17] Passive vulnerability indicators")
    passive_vuln_rows = compute_passive_vulnerability_indicators(web_rows, ssl_rows)
    write_csv(
        run_dir / "vulnerability_passive.csv",
        passive_vuln_rows,
        ["host", "category", "severity", "indicator", "evidence", "recommendation"],
    )

    print("[17/17] Reporting (CSV + HTML dashboard)")
    summary = {
        "generated_at": datetime.now().isoformat(),
        "domain": args.domain.strip().lower(),
        "related_domains_count": len(related_domains),
        "subdomains_count": len(all_subdomains),
        "resolved_hosts_count": with_records_count,
        "ips_count": len(ip_list),
        "shadow_assets_count": sum(1 for r in shadow_rows if r["is_shadow_it"] == "yes"),
        "high_or_critical_risk_count": sum(1 for r in risk_rows if r["risk_level"] in ("high", "critical")),
        "takeover_candidates_count": len(takeover_rows),
        "cloud_misconfig_count": len(cloud_rows),
        "email_security_high_risk_count": sum(1 for r in email_security_rows if r["risk_level"] == "high"),
        "passive_vuln_high_count": sum(1 for r in passive_vuln_rows if r["severity"] == "high"),
        "scanned_count": scanned_count,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    build_dashboard_html(
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

    print("\nKlaar. Output map:")
    print(run_dir)


if __name__ == "__main__":
    main()
