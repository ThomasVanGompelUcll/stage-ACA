import csv
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

DEFAULT_CUTOFF_DAYS = 7

API_KEY = "e8e1908b-64e3-4335-bb81-51c5c841b43a"
BASE_URL = "https://free.intelx.io"
DELAY = 1.0

HEADERS = {
    "X-Key": API_KEY,
    "User-Agent": "ACA-Darkweb-Monitor/1.0",
}


def load_env() -> None:
    load_dotenv()


def intelx_search(term: str, maxresults: int = 50) -> str:
    """
    Start een intelligente zoekopdracht (POST /intelligent/search)
    en retourneer de search_id (UUID).
    """
    url = f"{BASE_URL}/intelligent/search"
    payload = {
        "term": term,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": maxresults,
        "sort": 2,
        "media": 0,
        "timeout": 0,
    }

    response = requests.post(url, headers=HEADERS, json=payload)
    if response.status_code != 200:
        raise RuntimeError(f"Search error {response.status_code}: {response.text}")
    data = response.json()
    return data["id"]


def intelx_results(search_id: str, limit: int = 100) -> dict[str, Any]:
    """
    Haal resultaten op (GET /intelligent/search/result).
    """
    url = f"{BASE_URL}/intelligent/search/result"
    params = {"id": search_id, "limit": limit}
    response = requests.get(url, headers=HEADERS, params=params)
    if response.status_code != 200:
        raise RuntimeError(f"Result error {response.status_code}: {response.text}")
    return response.json()


def search_one(
    term: str,
    maxresults: int = 50,
    limit: int = 100,
    cutoff_days: int = DEFAULT_CUTOFF_DAYS,
) -> list[dict[str, Any]]:
    """
    Zoek 1 domein of 1 e-mail en retourneer de records.
    """
    print(f"[*] Searching: {term}")
    search_id = intelx_search(term, maxresults=maxresults)
    time.sleep(0.6)
    result = intelx_results(search_id, limit=limit)
    records = result.get("records", [])
    filtered = filter_by_date(records, cutoff_days)
    if filtered:
        print(f"[+] {len(filtered)} results for {term} (last {cutoff_days} days)")
    else:
        print(f"[-] No results for {term} in the last {cutoff_days} days")
    return filtered


def parse_record_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def get_cutoff_date(cutoff_days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=cutoff_days)


def filter_by_date(records: list[dict[str, Any]], cutoff_days: int) -> list[dict[str, Any]]:
    cutoff_date = get_cutoff_date(cutoff_days)
    filtered: list[dict[str, Any]] = []
    for record in records:
        date_value = record.get("date") or record.get("added")
        if not isinstance(date_value, str):
            continue
        parsed = parse_record_datetime(date_value)
        if parsed and parsed >= cutoff_date:
            filtered.append(record)
    return filtered


def collect_records(
    term: str,
    records: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    keys: set[str],
) -> None:
    for record in records:
        row: dict[str, Any] = {"term": term}
        for key, value in record.items():
            row[key] = value
            keys.add(key)
        rows.append(row)


def write_split_csv(rows: list[dict[str, Any]], keys: set[str], output_path: Path) -> None:
    fieldnames = ["term"] + sorted(keys)
    with output_path.open("w", encoding="utf-8", newline="") as outf:
        writer = csv.DictWriter(outf, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            normalized: dict[str, Any] = {}
            for key in fieldnames:
                value = row.get(key)
                if isinstance(value, (dict, list)):
                    normalized[key] = json.dumps(value, ensure_ascii=False)
                else:
                    normalized[key] = value
            writer.writerow(normalized)


def search_email_list(
    csv_file: Path,
    output_file: Path,
    maxresults: int,
    limit: int,
    cutoff_days: int,
    split_rows: list[dict[str, Any]],
    split_keys: set[str],
) -> None:
    """
    Zoek een lijst e-mails uit CSV met kolom 'email' en schrijf resultaten naar CSV.
    """
    with csv_file.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        emails = [(row.get("email") or "").strip() for row in reader]
        emails = [email for email in emails if email]

    print(f"[*] Loaded {len(emails)} emails from {csv_file}")

    with output_file.open("w", encoding="utf-8", newline="") as outf:
        writer = csv.writer(outf)
        writer.writerow(["email", "result_count", "records_json"])

        for email in emails:
            try:
                records = search_one(
                    email,
                    maxresults=maxresults,
                    limit=limit,
                    cutoff_days=cutoff_days,
                )
                writer.writerow([email, len(records), json.dumps(records, ensure_ascii=False)])
                collect_records(email, records, split_rows, split_keys)
            except Exception as error:
                print(f"[!] Error on {email}: {error}")
                writer.writerow([email, 0, json.dumps({"error": str(error)}, ensure_ascii=False)])
            finally:
                time.sleep(DELAY)


def with_timestamp(path: Path, timestamp: str) -> Path:
    if path.suffix:
        filename = f"{path.stem}_{timestamp}{path.suffix}"
    else:
        filename = f"{path.name}_{timestamp}"
    return path.with_name(filename)


def make_output_path(
    base_name: str,
    override: Path | None,
    timestamp: str,
    output_dir: Path,
) -> Path:
    if override:
        candidate = with_timestamp(override, timestamp)
    else:
        candidate = Path(f"{base_name}_{timestamp}.csv")
    return output_dir / candidate.name


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="IntelX Email/Domain Search")
    parser.add_argument("--email", help="Zoek een e-mail")
    parser.add_argument("--domain", help="Zoek een domein")
    parser.add_argument("--list", type=Path, help="CSV-lijst van e-mails (kolomnaam: email)")
    parser.add_argument("--out", type=Path, help="Output CSV pad (optioneel)")
    parser.add_argument("--limit", type=int, default=100, help="Max results per call (default 100)")
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_CUTOFF_DAYS,
        help="Aantal dagen terug (default 7)",
    )
    parser.add_argument(
        "--split-out",
        type=Path,
        help="Output CSV met 1 rij per record (optioneel)",
    )
    args = parser.parse_args()

    if not API_KEY or not BASE_URL:
        raise SystemExit("Configureer API_KEY en BASE_URL bovenaan het script.")

    load_env()
    cutoff_days_env = os.getenv("CUTOFF_DAYS")
    if cutoff_days_env and cutoff_days_env.isdigit():
        args.days = int(cutoff_days_env)

    split_rows: list[dict[str, Any]] = []
    split_keys: set[str] = set()
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_date = time.strftime("%d-%m-%Y")
    output_dir = Path("weekly") / run_date
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.email:
        run_type = "email"
        out_path = make_output_path(f"intelx-{run_type}", args.out, run_timestamp, output_dir)
        split_out_path = make_output_path(
            f"intelx-records-{run_type}",
            args.split_out,
            run_timestamp,
            output_dir,
        )
        records = search_one(
            args.email,
            maxresults=args.limit,
            limit=args.limit,
            cutoff_days=args.days,
        )
        with out_path.open("w", encoding="utf-8", newline="") as outf:
            writer = csv.writer(outf)
            writer.writerow(["email", "result_count", "records_json"])
            writer.writerow([args.email, len(records), json.dumps(records, ensure_ascii=False)])
        print(f"[+] Wrote results to {out_path}")
        collect_records(args.email, records, split_rows, split_keys)

    elif args.domain:
        run_type = "domain"
        out_path = make_output_path(f"intelx-{run_type}", args.out, run_timestamp, output_dir)
        split_out_path = make_output_path(
            f"intelx-records-{run_type}",
            args.split_out,
            run_timestamp,
            output_dir,
        )
        records = search_one(
            args.domain,
            maxresults=args.limit,
            limit=args.limit,
            cutoff_days=args.days,
        )
        with out_path.open("w", encoding="utf-8", newline="") as outf:
            writer = csv.writer(outf)
            writer.writerow(["domain", "result_count", "records_json"])
            writer.writerow([args.domain, len(records), json.dumps(records, ensure_ascii=False)])
        print(f"[+] Wrote results to {out_path}")
        collect_records(args.domain, records, split_rows, split_keys)

    elif args.list:
        run_type = "list"
        out_path = make_output_path(f"intelx-{run_type}", args.out, run_timestamp, output_dir)
        split_out_path = make_output_path(
            f"intelx-records-{run_type}",
            args.split_out,
            run_timestamp,
            output_dir,
        )
        search_email_list(
            args.list,
            out_path,
            maxresults=args.limit,
            limit=args.limit,
            cutoff_days=args.days,
            split_rows=split_rows,
            split_keys=split_keys,
        )

    else:
        print("Gebruik:")
        print("  python intelx.py --email user@example.com")
        print("  python intelx.py --domain example.com")
        print("  python intelx.py --list emails.csv --out results.csv")
        return

    if split_rows:
        write_split_csv(split_rows, split_keys, split_out_path)
        print(f"[+] Wrote split records to {split_out_path}")
    else:
        print(f"[-] No results found in the last {args.days} days")


if __name__ == "__main__":
    main()