import csv
import importlib.util
import re
from pathlib import Path


def load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Kon module niet laden: {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sanitize_slug(value):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value.strip().lower()).replace(".", "_")


def write_csv(path, rows, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in columns})


def read_official_domains(domain, official_domains_file):
    official = {domain.lower()}
    if official_domains_file and official_domains_file.exists():
        for line in official_domains_file.read_text(encoding="utf-8").splitlines():
            value = line.strip().lower()
            if value:
                official.add(value)
    return sorted(official)


def is_under_official_domain(hostname, official_domains):
    host = hostname.lower().strip()
    for official in official_domains:
        if host == official or host.endswith(f".{official}"):
            return True
    return False
