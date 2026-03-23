import argparse
import csv
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run_az_json(args: list[str], allow_error: bool = False) -> Any:
    command = ["az", *args, "-o", "json"]
    proc = subprocess.run(command, capture_output=True, text=True)

    if proc.returncode != 0:
        if allow_error:
            return None
        message = proc.stderr.strip() or proc.stdout.strip() or "unknown azure cli error"
        raise RuntimeError(f"Azure CLI command failed: {' '.join(command)}\n{message}")

    output = proc.stdout.strip()
    if not output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse JSON from command: {' '.join(command)}") from exc


def ensure_az_login() -> dict[str, Any]:
    account = run_az_json(["account", "show"])
    if not isinstance(account, dict):
        raise RuntimeError("Could not read Azure account context. Run 'az login' first.")
    return account


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)


def to_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def resource_row(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": resource.get("id", ""),
        "name": resource.get("name", ""),
        "type": resource.get("type", ""),
        "kind": resource.get("kind", ""),
        "location": resource.get("location", ""),
        "resource_group": resource.get("resourceGroup", ""),
        "subscription_id": resource.get("subscriptionId", ""),
        "managed_by": resource.get("managedBy", ""),
    }


def detect_connection_keys(settings: list[dict[str, Any]]) -> list[str]:
    patterns = (
        "connection",
        "database",
        "db_",
        "sql",
        "storage",
        "redis",
        "servicebus",
        "keyvault",
    )

    keys: list[str] = []
    for item in settings:
        key = str(item.get("name", "")).strip()
        lowered = key.lower()
        if key and any(pattern in lowered for pattern in patterns):
            keys.append(key)
    return sorted(set(keys))


def collect_webapp_relationships(resource: dict[str, Any], include_app_settings: bool) -> dict[str, Any]:
    rg = str(resource.get("resourceGroup", ""))
    name = str(resource.get("name", ""))

    rel: dict[str, Any] = {
        "resource_id": resource.get("id", ""),
        "resource_name": name,
        "resource_type": resource.get("type", ""),
        "identity_type": "",
        "principal_id": "",
        "tenant_id": "",
        "github_repo": "",
        "github_branch": "",
        "potential_connection_keys": [],
    }

    identity = run_az_json(["webapp", "identity", "show", "-g", rg, "-n", name], allow_error=True)
    if isinstance(identity, dict):
        rel["identity_type"] = identity.get("type", "") or ""
        rel["principal_id"] = identity.get("principalId", "") or ""
        rel["tenant_id"] = identity.get("tenantId", "") or ""

    deployment = run_az_json(["webapp", "deployment", "source", "show", "-g", rg, "-n", name], allow_error=True)
    if isinstance(deployment, dict):
        rel["github_repo"] = deployment.get("repoUrl", "") or ""
        rel["github_branch"] = deployment.get("branch", "") or ""

    if include_app_settings:
        settings = run_az_json(["webapp", "config", "appsettings", "list", "-g", rg, "-n", name], allow_error=True)
        if isinstance(settings, list):
            rel["potential_connection_keys"] = detect_connection_keys(settings)

    return rel


def build_report(resources: list[dict[str, Any]], account: dict[str, Any], include_app_settings: bool) -> dict[str, Any]:
    type_counts = Counter(str(resource.get("type", "unknown")).lower() for resource in resources)

    webapps = [
        resource
        for resource in resources
        if str(resource.get("type", "")).lower() == "microsoft.web/sites"
    ]

    relationships = [collect_webapp_relationships(webapp, include_app_settings) for webapp in webapps]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": account.get("tenantId", ""),
        "subscription_id": account.get("id", ""),
        "subscription_name": account.get("name", ""),
        "resource_count": len(resources),
        "webapp_count": len(webapps),
        "resource_type_counts": dict(sorted(type_counts.items())),
        "resources": [resource_row(resource) for resource in resources],
        "relationships": relationships,
    }


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_resources_csv(path: Path, resources: list[dict[str, Any]]) -> None:
    columns = [
        "id",
        "name",
        "type",
        "kind",
        "location",
        "resource_group",
        "subscription_id",
        "managed_by",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for resource in resources:
            writer.writerow({column: to_string(resource.get(column, "")) for column in columns})


def write_relationships_csv(path: Path, relationships: list[dict[str, Any]]) -> None:
    columns = [
        "resource_id",
        "resource_name",
        "resource_type",
        "identity_type",
        "principal_id",
        "tenant_id",
        "github_repo",
        "github_branch",
        "potential_connection_keys",
    ]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in relationships:
            formatted = dict(row)
            formatted["potential_connection_keys"] = "; ".join(row.get("potential_connection_keys", []))
            writer.writerow({column: to_string(formatted.get(column, "")) for column in columns})


def write_summary_md(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Azure Discovery Summary",
        "",
        f"- Generated at: {report.get('generated_at', '')}",
        f"- Subscription: {report.get('subscription_name', '')} ({report.get('subscription_id', '')})",
        f"- Tenant: {report.get('tenant_id', '')}",
        f"- Total resources: {report.get('resource_count', 0)}",
        f"- Web apps/functions (Microsoft.Web/sites): {report.get('webapp_count', 0)}",
        "",
        "## Resource Types",
        "",
    ]

    type_counts: dict[str, int] = report.get("resource_type_counts", {})
    if type_counts:
        for type_name, count in type_counts.items():
            lines.append(f"- {type_name}: {count}")
    else:
        lines.append("- No resources found")

    lines.extend(["", "## Relationship Coverage", ""])
    rels: list[dict[str, Any]] = report.get("relationships", [])
    if rels:
        lines.append("- Web app identities and deployment-source hints collected.")
        with_identity = sum(1 for rel in rels if rel.get("principal_id"))
        with_repo = sum(1 for rel in rels if rel.get("github_repo"))
        lines.append(f"- Web apps with managed identity: {with_identity}/{len(rels)}")
        lines.append(f"- Web apps with GitHub deployment source: {with_repo}/{len(rels)}")
    else:
        lines.append("- No Microsoft.Web/sites resources found, so no app relationships extracted.")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Azure environment discovery: inventory + workload relationship hints",
    )
    parser.add_argument(
        "--subscription",
        help="Optional subscription ID or name. If omitted, active Azure CLI subscription is used.",
    )
    parser.add_argument(
        "--output-dir",
        default="azure/output",
        help="Output directory for reports (default: azure/output).",
    )
    parser.add_argument(
        "--include-app-settings",
        action="store_true",
        help="Include app-setting key-name analysis (no values exported).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    account = ensure_az_login()

    if args.subscription:
        subprocess.run(["az", "account", "set", "--subscription", args.subscription], check=True)
        account = ensure_az_login()

    resources = run_az_json(["resource", "list"])
    if not isinstance(resources, list):
        raise RuntimeError("Unexpected result from 'az resource list'.")

    report = build_report(resources, account, include_app_settings=args.include_app_settings)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_token = sanitize_filename(str(account.get("id", "subscription"))[:18] or "subscription")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"azure_inventory_{sub_token}_{stamp}.json"
    resources_csv_path = output_dir / f"azure_resources_{sub_token}_{stamp}.csv"
    rel_csv_path = output_dir / f"azure_relationships_{sub_token}_{stamp}.csv"
    summary_path = output_dir / f"azure_summary_{sub_token}_{stamp}.md"

    write_json(json_path, report)
    write_resources_csv(resources_csv_path, report.get("resources", []))
    write_relationships_csv(rel_csv_path, report.get("relationships", []))
    write_summary_md(summary_path, report)

    print(f"[OK] Inventory JSON: {json_path}")
    print(f"[OK] Resources CSV: {resources_csv_path}")
    print(f"[OK] Relationships CSV: {rel_csv_path}")
    print(f"[OK] Summary Markdown: {summary_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
