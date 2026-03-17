import requests
import argparse
from pathlib import Path
from datetime import datetime
import re


def is_valid_subdomain_for_domain(value, domain):
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
    if candidate == domain:
        return True
    return candidate.endswith(f".{domain}")

def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(url, timeout=20)
    response.raise_for_status()

    data = response.json()
    normalized_domain = domain.strip().lower()
    names = []
    for item in data:
        value = item.get("name_value", "")
        if not value:
            continue
        for line in value.splitlines():
            cleaned = line.strip().lower()
            if not cleaned:
                continue
            if is_valid_subdomain_for_domain(cleaned, normalized_domain):
                names.append(cleaned.removeprefix("*."))

    return sorted(set(names))


def sanitize_domain(domain):
    return re.sub(r"[^a-zA-Z0-9.-]", "_", domain).replace(".", "_")


def save_subdomains_file(domain, subdomains, results_dir):
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    output_file = results_dir / f"subdomains_{sanitize_domain(domain)}_{timestamp}.txt"
    output_file.write_text("\n".join(subdomains), encoding="utf-8")
    return output_file


def run(domain, results_dir):
    subdomains = fetch_subdomains(domain)
    output_file = save_subdomains_file(domain, subdomains, results_dir)
    return output_file, len(subdomains)


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch subdomains from crt.sh")
    parser.add_argument("--domain", default="aca-it.nl", help="Domain to query")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent / "results"),
        help="Directory where the output txt file is stored",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    output_file, count = run(args.domain, Path(args.output_dir))
    print(f"{count} resultaten opgeslagen in: {output_file}")