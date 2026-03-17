import requests
import argparse
from pathlib import Path
from datetime import datetime
import csv

SEC_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy"
]


def get_input_file(scripts_dir):
    preferred = sorted(scripts_dir.glob("subdomains_*.txt"))
    candidates = preferred if preferred else sorted(scripts_dir.glob("*.txt"))

    if not candidates:
        raise FileNotFoundError("Geen .txt bestand gevonden in de scripts-map.")

    if len(candidates) > 1:
        return max(candidates, key=lambda path: path.stat().st_mtime)

    return candidates[0]


def load_urls(input_file):
    domains = []
    for line in input_file.read_text(encoding="utf-8").splitlines():
        value = line.strip().lower()
        if not value:
            continue
        if value.startswith("*."):
            continue
        domains.append(value)

    unique_domains = sorted(set(domains))
    return [f"https://{domain}" for domain in unique_domains]


def fingerprint(url):
    result = {
        "url": url,
        "status": "",
        "final_url": "",
        "server": "",
        "error": "",
        "cookies": "",
        "headers": {}
    }

    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
    except Exception as e:
        result["error"] = str(e)
        return result

    result["status"] = r.status_code
    result["final_url"] = r.url
    result["server"] = r.headers.get("Server", "N/A")

    for h in SEC_HEADERS:
        val = r.headers.get(h)
        result["headers"][h] = val if val else "MISSING"

    cookies = r.cookies.get_dict()
    if cookies:
        result["cookies"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    else:
        result["cookies"] = "none"

    return result


def write_results(results_dir, input_file, scan_results):
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = results_dir / f"web_scan_{input_file.stem}_{timestamp}.csv"

    columns = ["source_file", "scan_timestamp", "url", "status", "final_url", "server", "error", "cookies"] + SEC_HEADERS

    with output_file.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()

        for item in scan_results:
            row = {
                "source_file": input_file.name,
                "scan_timestamp": timestamp,
                "url": item["url"],
                "status": item["status"],
                "final_url": item["final_url"],
                "server": item["server"],
                "error": item["error"],
                "cookies": item["cookies"],
            }
            for header in SEC_HEADERS:
                row[header] = item["headers"].get(header, "")

            writer.writerow(row)

    return output_file


def run(input_file, results_dir):
    urls = load_urls(input_file)

    scan_results = []
    for url in urls:
        print(f"Scannen: {url}")
        scan_results.append(fingerprint(url))

    output_file = write_results(results_dir, input_file, scan_results)
    success_count = sum(1 for result in scan_results if not result["error"])
    return output_file, len(scan_results), success_count


def parse_args():
    base_dir = Path(__file__).resolve().parent
    scripts_dir = base_dir.parent
    parser = argparse.ArgumentParser(description="Scan web services for subdomains")
    parser.add_argument(
        "--input-file",
        help="Path to the txt file with subdomains. If omitted, auto-detects in scripts folder.",
    )
    parser.add_argument(
        "--results-dir",
        default=str(base_dir / "results"),
        help="Directory where the web scan CSV result is stored",
    )
    parser.add_argument(
        "--search-dir",
        default=str(scripts_dir),
        help="Directory used for auto-detecting input txt when --input-file is omitted",
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    input_file = Path(args.input_file) if args.input_file else get_input_file(Path(args.search_dir))
    results_dir = Path(args.results_dir)

    output_file, scanned_count, success_count = run(input_file, results_dir)
    print(f"Input: {input_file.name}")
    print(f"Gescand: {scanned_count} URLs")
    print(f"Succesvol: {success_count}")
    print(f"Resultaat opgeslagen in: {output_file}")