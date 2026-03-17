import re
import socket
import ssl
from datetime import datetime, timezone

import requests

from discovery_pipeline.constants import SEC_HEADERS


def scan_web_asset(host, scheme):
    url = f"{scheme}://{host}"
    row = {
        "host": host,
        "url": url,
        "scheme": scheme,
        "status": "",
        "final_url": "",
        "server": "",
        "x_powered_by": "",
        "generator": "",
        "title": "",
        "error": "",
    }
    for header in SEC_HEADERS:
        row[header] = ""

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        row["status"] = response.status_code
        row["final_url"] = response.url
        row["server"] = response.headers.get("Server", "")
        row["x_powered_by"] = response.headers.get("X-Powered-By", "")
        row["generator"] = response.headers.get("X-Generator", "")
        body = response.text[:100000]

        title_match = re.search(r"<title>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        if title_match:
            row["title"] = re.sub(r"\s+", " ", title_match.group(1)).strip()

        for header in SEC_HEADERS:
            row[header] = response.headers.get(header, "MISSING")
    except Exception as e:
        row["error"] = str(e)

    return row


def ssl_scan_host(host):
    result = {
        "host": host,
        "ssl_ok": False,
        "issuer": "",
        "subject": "",
        "serial_number": "",
        "not_before": "",
        "not_after": "",
        "days_left": "",
        "error": "",
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()

        issuer = cert.get("issuer", ())
        subject = cert.get("subject", ())
        issuer_text = ", ".join("=".join(x) for item in issuer for x in item)
        subject_text = ", ".join("=".join(x) for item in subject for x in item)

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        days_left = ""
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days

        result.update(
            {
                "ssl_ok": True,
                "issuer": issuer_text,
                "subject": subject_text,
                "serial_number": cert.get("serialNumber", ""),
                "not_before": not_before,
                "not_after": not_after,
                "days_left": days_left,
            }
        )
    except Exception as e:
        result["error"] = str(e)

    return result
