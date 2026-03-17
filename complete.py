"""Compatibility facade for the modular discovery pipeline.

This module keeps the original public API so existing imports continue to work,
while the implementation lives in dedicated scripts under discovery_pipeline/.
"""

from discovery_pipeline.analysis.assets import compute_risk_scores, detect_shadow_it, fingerprint_assets
from discovery_pipeline.analysis.security import (
    compute_passive_vulnerability_indicators,
    detect_cloud_misconfigurations,
    detect_subdomain_takeover_risks,
    evaluate_email_security,
)
from discovery_pipeline.constants import CLOUD_ENDPOINT_PATTERNS, SEC_HEADERS, TAKEOVER_FINGERPRINTS, TOOL_PATH_OVERRIDES
from discovery_pipeline.core.utils import (
    is_under_official_domain,
    load_module,
    read_official_domains,
    sanitize_slug,
    write_csv,
)
from discovery_pipeline.discovery.enumeration import run_external_subdomain_tools
from discovery_pipeline.discovery.whois_ct import (
    collect_ct_data,
    fetch_subdomains_bufferover,
    fetch_subdomains_crtsh,
    fetch_subdomains_hackertarget,
    is_valid_subdomain_for_domain,
    normalize_subdomain_candidate,
    run_whois_discovery,
)
from discovery_pipeline.orchestrator import main, parse_args
from discovery_pipeline.reporting.dashboard import build_dashboard_html
from discovery_pipeline.scanning.network import build_reverse_ip_clusters, lookup_asn_ipinfo, parse_dns_csv, resolve_dns_values
from discovery_pipeline.scanning.web import scan_web_asset, ssl_scan_host


__all__ = [
    "SEC_HEADERS",
    "TAKEOVER_FINGERPRINTS",
    "CLOUD_ENDPOINT_PATTERNS",
    "TOOL_PATH_OVERRIDES",
    "load_module",
    "sanitize_slug",
    "write_csv",
    "read_official_domains",
    "is_under_official_domain",
    "run_whois_discovery",
    "is_valid_subdomain_for_domain",
    "normalize_subdomain_candidate",
    "fetch_subdomains_crtsh",
    "fetch_subdomains_bufferover",
    "fetch_subdomains_hackertarget",
    "collect_ct_data",
    "run_external_subdomain_tools",
    "parse_dns_csv",
    "resolve_dns_values",
    "evaluate_email_security",
    "detect_subdomain_takeover_risks",
    "compute_passive_vulnerability_indicators",
    "detect_cloud_misconfigurations",
    "build_reverse_ip_clusters",
    "lookup_asn_ipinfo",
    "scan_web_asset",
    "ssl_scan_host",
    "fingerprint_assets",
    "detect_shadow_it",
    "compute_risk_scores",
    "build_dashboard_html",
    "parse_args",
    "main",
]


if __name__ == "__main__":
    main()
