import html
from collections import defaultdict


def build_dashboard_html(output_file, summary, report):
    def esc(value):
        return html.escape(str(value if value is not None else ""))

    def level_badge(level):
        level_value = (level or "").lower()
        color = {
            "critical": "#8b0000",
            "high": "#c2410c",
            "medium": "#b45309",
            "low": "#166534",
        }.get(level_value, "#334155")
        return f"<span class='badge' style='background:{color}'>{esc(level_value or 'unknown')}</span>"

    def render_table(columns, rows, max_rows=25):
        if not rows:
            return "<p class='muted'>Geen data beschikbaar.</p>"
        head = "".join(f"<th>{esc(col)}</th>" for col in columns)
        body_rows = []
        for row in rows[:max_rows]:
            cells = "".join(f"<td>{esc(row.get(col, ''))}</td>" for col in columns)
            body_rows.append(f"<tr>{cells}</tr>")
        return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"

    risk_rows = report.get("risk_rows", [])
    shadow_rows = report.get("shadow_rows", [])
    ssl_rows = report.get("ssl_rows", [])
    web_rows = report.get("web_rows", [])
    ct_rows = report.get("ct_rows", [])
    asn_rows = report.get("asn_rows", [])
    reverse_ip_rows = report.get("reverse_ip_rows", [])
    fingerprint_rows = report.get("fingerprint_rows", [])
    whois_data = report.get("whois_data", {})
    tool_logs = report.get("tool_logs", [])
    email_security_rows = report.get("email_security_rows", [])
    takeover_rows = report.get("takeover_rows", [])
    cloud_rows = report.get("cloud_rows", [])
    passive_vuln_rows = report.get("passive_vuln_rows", [])

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in risk_rows:
        level = str(row.get("risk_level", "")).lower()
        if level in risk_counts:
            risk_counts[level] += 1

    ssl_ok_count = sum(1 for row in ssl_rows if row.get("ssl_ok"))
    ssl_fail_count = len(ssl_rows) - ssl_ok_count

    status_2xx = sum(1 for row in web_rows if str(row.get("status", "")).startswith("2"))
    status_3xx = sum(1 for row in web_rows if str(row.get("status", "")).startswith("3"))
    status_4xx = sum(1 for row in web_rows if str(row.get("status", "")).startswith("4"))
    status_5xx = sum(1 for row in web_rows if str(row.get("status", "")).startswith("5"))
    status_error = sum(1 for row in web_rows if row.get("error"))

    provider_counts = defaultdict(int)
    framework_counts = defaultdict(int)
    for row in fingerprint_rows:
        if row.get("provider"):
            provider_counts[row["provider"]] += 1
        if row.get("frameworks"):
            for framework in [x.strip() for x in row["frameworks"].split(",") if x.strip()]:
                framework_counts[framework] += 1

    top_providers = sorted(provider_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_frameworks = sorted(framework_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    max_risk_count = max(1, max(risk_counts.values()))
    max_status_count = max(1, max(status_2xx, status_3xx, status_4xx, status_5xx, status_error))

    risk_chart = "".join(
        [
            f"<div class='bar-row'><span>{label}</span><div class='bar'><div style='width:{(count / max_risk_count) * 100:.1f}%'>{count}</div></div></div>"
            for label, count in [("critical", risk_counts["critical"]), ("high", risk_counts["high"]), ("medium", risk_counts["medium"]), ("low", risk_counts["low"])]
        ]
    )

    status_chart = "".join(
        [
            f"<div class='bar-row'><span>{label}</span><div class='bar'><div style='width:{(count / max_status_count) * 100:.1f}%'>{count}</div></div></div>"
            for label, count in [("2xx", status_2xx), ("3xx", status_3xx), ("4xx", status_4xx), ("5xx", status_5xx), ("errors", status_error)]
        ]
    )

    provider_list = "".join([f"<li>{esc(name)} <strong>({count})</strong></li>" for name, count in top_providers])
    framework_list = "".join([f"<li>{esc(name)} <strong>({count})</strong></li>" for name, count in top_frameworks])
    provider_fallback = "<li class='muted'>Geen providers gedetecteerd.</li>"
    framework_fallback = "<li class='muted'>Geen frameworks gedetecteerd.</li>"

    whois_info_html = f"""
    <ul>
      <li><strong>Domain:</strong> {esc(whois_data.get('domain', ''))}</li>
      <li><strong>Registrar:</strong> {esc(whois_data.get('registrar', ''))}</li>
      <li><strong>Name:</strong> {esc(whois_data.get('name', ''))}</li>
      <li><strong>Organization:</strong> {esc(whois_data.get('org', ''))}</li>
      <li><strong>Emails:</strong> {esc(', '.join(whois_data.get('emails', [])))}</li>
      <li><strong>Nameservers:</strong> {esc(', '.join(whois_data.get('nameservers', [])))}</li>
      <li><strong>Related domains found:</strong> {esc(len(whois_data.get('related_domains', [])))}</li>
    </ul>
    """

    top_risks_html = "".join(
        [
            f"<tr><td>{esc(r.get('asset'))}</td><td>{esc(r.get('risk_score'))}</td><td>{level_badge(r.get('risk_level'))}</td><td>{esc(r.get('reasons'))}</td></tr>"
            for r in risk_rows[:30]
        ]
    )

    shadow_only = [row for row in shadow_rows if row.get("is_shadow_it") == "yes"]
    takeover_high = sum(1 for row in takeover_rows if row.get("severity") == "high")
    cloud_potential = sum(1 for row in cloud_rows if row.get("status") == "potential")
    passive_vuln_high = sum(1 for row in passive_vuln_rows if row.get("severity") == "high")

    page_html = f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Discovery Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; color: #1f2937; background: #f8fafc; }}
    h1, h2, h3 {{ margin: 8px 0; }}
    p {{ margin: 6px 0; }}
    .section {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; margin-bottom: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 10px; margin-top: 10px; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; background: #f9fafb; }}
    .card .kpi {{ font-size: 22px; font-weight: 700; margin-top: 3px; }}
    .flex {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .col {{ flex: 1 1 380px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 7px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    .badge {{ color: #fff; border-radius: 999px; padding: 2px 8px; font-size: 12px; text-transform: uppercase; }}
    .muted {{ color: #64748b; }}
    .bar-row {{ display: grid; grid-template-columns: 70px 1fr; align-items: center; gap: 8px; margin: 6px 0; font-size: 13px; }}
    .bar {{ background: #e2e8f0; border-radius: 999px; overflow: hidden; }}
    .bar > div {{ background: #2563eb; color: #fff; min-height: 20px; padding-left: 6px; display: flex; align-items: center; }}
    ul {{ margin: 8px 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <h1>Automated Discovery Dashboard</h1>
  <p class=\"muted\">Generated at: {esc(summary.get('generated_at'))}</p>

  <div class=\"section\">
    <h2>Executive Summary</h2>
    <div class=\"grid\">
      <div class=\"card\"><div>Root domain</div><div class=\"kpi\">{esc(summary.get('domain'))}</div></div>
      <div class=\"card\"><div>Related domains</div><div class=\"kpi\">{esc(summary.get('related_domains_count'))}</div></div>
      <div class=\"card\"><div>Subdomains</div><div class=\"kpi\">{esc(summary.get('subdomains_count'))}</div></div>
      <div class=\"card\"><div>Resolved hosts</div><div class=\"kpi\">{esc(summary.get('resolved_hosts_count'))}</div></div>
      <div class=\"card\"><div>IPs</div><div class=\"kpi\">{esc(summary.get('ips_count'))}</div></div>
      <div class=\"card\"><div>Shadow IT assets</div><div class=\"kpi\">{esc(summary.get('shadow_assets_count'))}</div></div>
      <div class=\"card\"><div>High/Critical risks</div><div class=\"kpi\">{esc(summary.get('high_or_critical_risk_count'))}</div></div>
      <div class=\"card\"><div>Total scanned hosts</div><div class=\"kpi\">{esc(summary.get('subdomains_count'))}</div></div>
    </div>
  </div>

  <div class=\"section\">
    <h2>Risk Overview</h2>
    <div class=\"flex\">
      <div class=\"col\">
        <h3>Risk Levels</h3>
        {risk_chart}
      </div>
      <div class="col">
        <h3>Top Risk Assets</h3>
        <table>
          <thead><tr><th>Asset</th><th>Score</th><th>Level</th><th>Reasons</th></tr></thead>
          <tbody>{top_risks_html}</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class=\"section\">
    <h2>Exposure & SSL Health</h2>
    <div class=\"flex\">
      <div class=\"col\">
        <h3>Web Status Distribution</h3>
        {status_chart}
      </div>
      <div class=\"col\">
        <h3>SSL Summary</h3>
        <ul>
          <li><strong>SSL ok:</strong> {esc(ssl_ok_count)}</li>
          <li><strong>SSL failed:</strong> {esc(ssl_fail_count)}</li>
          <li><strong>HTTPS rows:</strong> {esc(sum(1 for r in web_rows if r.get('scheme') == 'https'))}</li>
          <li><strong>HTTP rows:</strong> {esc(sum(1 for r in web_rows if r.get('scheme') == 'http'))}</li>
        </ul>
      </div>
    </div>
  </div>

  <div class=\"section\">
    <h2>WHOIS & CT Intelligence</h2>
    <div class=\"flex\">
      <div class=\"col\">
        <h3>WHOIS Profile</h3>
        {whois_info_html}
      </div>
      <div class=\"col\">
        <h3>CT Discoveries</h3>
        <p><strong>Total CT entries:</strong> {esc(len(ct_rows))}</p>
        {render_table(['source_domain', 'discovered_name', 'source'], ct_rows, max_rows=20)}
      </div>
    </div>
  </div>

  <div class=\"section\">
    <h2>Infrastructure & Fingerprinting</h2>
    <div class=\"flex\">
      <div class=\"col\">
        <h3>Top Providers</h3>
        <ul>{provider_list if provider_list else provider_fallback}</ul>
        <h3>Top Frameworks</h3>
        <ul>{framework_list if framework_list else framework_fallback}</ul>
      </div>
      <div class=\"col\">
        <h3>Tool Status</h3>
        {render_table(['tool', 'return_code', 'items', 'error'], tool_logs, max_rows=10)}
      </div>
    </div>
    <h3>Fingerprinting Details</h3>
    {render_table(['host', 'scheme', 'provider', 'ip', 'server', 'technologies', 'frameworks', 'title'], fingerprint_rows, max_rows=40)}
  </div>

  <div class=\"section\">
    <h2>Email Security</h2>
    <ul>
      <li><strong>Domains checked:</strong> {esc(len(email_security_rows))}</li>
      <li><strong>Rows with high risk:</strong> {esc(sum(1 for r in email_security_rows if r.get('risk_level') == 'high'))}</li>
    </ul>
    {render_table(['domain', 'mx_count', 'spf_mode', 'dmarc_policy', 'dkim_status', 'mta_sts', 'tls_rpt', 'risk_level', 'issues'], email_security_rows, max_rows=20)}
  </div>

  <div class=\"section\">
    <h2>Takeover & Cloud Misconfig</h2>
    <div class=\"grid\">
      <div class=\"card\"><div>Takeover candidates (high)</div><div class=\"kpi\">{esc(takeover_high)}</div></div>
      <div class=\"card\"><div>Cloud findings (potential)</div><div class=\"kpi\">{esc(cloud_potential)}</div></div>
      <div class=\"card\"><div>Passive vuln (high)</div><div class=\"kpi\">{esc(passive_vuln_high)}</div></div>
      <div class=\"card\"><div>Total passive findings</div><div class=\"kpi\">{esc(len(passive_vuln_rows))}</div></div>
    </div>
    <h3>Subdomain Takeover Candidates</h3>
    {render_table(['host', 'cname', 'provider', 'finding', 'severity', 'confidence', 'recommendation'], takeover_rows, max_rows=40)}
    <h3>Cloud Misconfiguration Signals</h3>
    {render_table(['asset', 'provider', 'check', 'severity', 'status', 'evidence', 'recommendation'], cloud_rows, max_rows=40)}
    <h3>Passive Vulnerability Indicators</h3>
    {render_table(['host', 'category', 'severity', 'indicator', 'evidence', 'recommendation'], passive_vuln_rows, max_rows=60)}
  </div>

  <div class=\"section\">
    <h2>Network Intelligence</h2>
    <div class=\"flex\">
      <div class=\"col\">
        <h3>ASN Lookup</h3>
        {render_table(['ip', 'asn', 'org', 'hostname', 'country'], asn_rows, max_rows=30)}
      </div>
      <div class=\"col\">
        <h3>Reverse IP Clusters</h3>
        {render_table(['ip', 'local_hosts_count', 'external_hosts_count'], reverse_ip_rows, max_rows=30)}
      </div>
    </div>
  </div>

  <div class=\"section\">
    <h2>Shadow IT</h2>
    <p><strong>Detected Shadow IT assets:</strong> {esc(len(shadow_only))}</p>
    {render_table(['asset', 'is_shadow_it', 'matched_official_domain'], shadow_rows, max_rows=60)}
  </div>

  <div class=\"section\">
    <h2>SSL Details</h2>
    {render_table(['host', 'ssl_ok', 'issuer', 'not_after', 'days_left', 'error'], ssl_rows, max_rows=50)}
  </div>

</body>
</html>
"""
    output_file.write_text(page_html, encoding="utf-8")
