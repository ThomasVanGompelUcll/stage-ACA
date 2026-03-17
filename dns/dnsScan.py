import dns.resolver
import argparse
from pathlib import Path
from datetime import datetime
import re
import csv

record_types = ["A", "AAAA", "CNAME", "TXT"]


def get_single_input_file(base_dir):
    txt_files = [
        path for path in base_dir.glob("*.txt") if path.is_file() and path.parent.name != "resultaten"
    ]

    if len(txt_files) == 0:
        raise FileNotFoundError("Geen .txt inputbestand gevonden in de dns-map.")

    if len(txt_files) > 1:
        names = "\n- ".join(path.name for path in txt_files)
        raise ValueError(
            "Er zijn meerdere .txt bestanden gevonden. Hou precies 1 inputbestand in deze map.\n"
            f"- {names}"
        )

    return txt_files[0]


def load_subdomains(input_file):
    entries = []
    for line in input_file.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith("*."):
            continue
        entries.append(value.lower())

    return sorted(set(entries))

def resolve_record(domain, rtype):
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=2)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def scan_domain(domain):
    found = {}
    for rtype in record_types:
        records = resolve_record(domain, rtype)
        if records:
            found[rtype] = records
    return found


def sanitize_filename(value):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)


def write_results(results_dir, source_file, useful_results):
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    output_name = f"dns_scan_{sanitize_filename(source_file.stem)}__{timestamp}.csv"
    output_file = results_dir / output_name

    with output_file.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["source_file", "scan_timestamp", "domain", "record_type", "value"])
        for domain in sorted(useful_results):
            for rtype in record_types:
                if rtype in useful_results[domain]:
                    for rec in useful_results[domain][rtype]:
                        writer.writerow([source_file.name, timestamp, domain, rtype, rec])

    return output_file


def run(input_file, results_dir):
    subdomains = load_subdomains(input_file)

    useful_results = {}
    for sub in subdomains:
        result = scan_domain(sub)
        if result:
            useful_results[sub] = result

    output_file = write_results(results_dir, input_file, useful_results)
    return output_file, len(subdomains), len(useful_results)


def parse_args():
    base_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Scan DNS records for subdomains")
    parser.add_argument(
        "--input-file",
        help="Path to the txt file with subdomains. If omitted, auto-detects a single txt in dns folder.",
    )
    parser.add_argument(
        "--results-dir",
        default=str(base_dir / "resultaten"),
        help="Directory where the DNS CSV result is stored",
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    base_dir = Path(__file__).resolve().parent
    input_file = Path(args.input_file) if args.input_file else get_single_input_file(base_dir)
    results_dir = Path(args.results_dir)

    output_file, scanned_count, records_count = run(input_file, results_dir)

    print(f"Input: {input_file.name}")
    print(f"Gescand: {scanned_count} subdomeinen")
    print(f"Met records: {records_count}")
    print(f"Resultaat opgeslagen in: {output_file}")
