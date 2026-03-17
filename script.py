import argparse
from datetime import datetime
import importlib.util
from pathlib import Path
import re


def load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Kon module niet laden: {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args():
    parser = argparse.ArgumentParser(
        description="Voer domain, dns en webService scan in 1 keer uit"
    )
    parser.add_argument("--domain", required=True, help="Domein om te scannen")
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Map voor alle outputbestanden (default: scripts/results)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    scripts_dir = Path(__file__).resolve().parent
    results_dir = (scripts_dir / args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    domain_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", args.domain.strip().lower()).replace(".", "_")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_results_dir = results_dir / f"{domain_slug}_{timestamp}"
    run_results_dir.mkdir(parents=True, exist_ok=True)

    domain_module = load_module("domain_module", scripts_dir / "domain" / "domain.py")
    dns_module = load_module("dns_module", scripts_dir / "dns" / "dnsScan.py")
    web_module = load_module("web_module", scripts_dir / "webService" / "webService.py")

    print(f"[1/3] Subdomeinen ophalen voor: {args.domain}")
    subdomains_file, subdomain_count = domain_module.run(args.domain, run_results_dir)
    print(f"  - {subdomain_count} subdomeinen opgeslagen in: {subdomains_file}")

    print("[2/3] DNS records scannen")
    dns_output_file, scanned_count, with_records_count = dns_module.run(subdomains_file, run_results_dir)
    print(f"  - Gescand: {scanned_count}, met records: {with_records_count}")
    print(f"  - DNS resultaat: {dns_output_file}")

    print("[3/3] Web services scannen")
    web_output_file, url_count, success_count = web_module.run(subdomains_file, run_results_dir)
    print(f"  - Gescand: {url_count} URLs, succesvol: {success_count}")
    print(f"  - Web resultaat: {web_output_file}")

    print("\nKlaar. Alle resultaten staan in:")
    print(f"{run_results_dir}")


if __name__ == "__main__":
    main()
