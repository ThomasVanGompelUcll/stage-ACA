import shutil
import subprocess
from pathlib import Path

from discovery_pipeline.constants import TOOL_PATH_OVERRIDES


def run_external_subdomain_tools(domain):
    discovered = set()
    tool_logs = []

    def resolve_tool_binary(tool_name):
        in_path = shutil.which(tool_name)
        if in_path:
            return in_path
        for candidate in TOOL_PATH_OVERRIDES.get(tool_name, []):
            if candidate and Path(candidate).exists():
                return candidate
        return ""

    subfinder_bin = resolve_tool_binary("subfinder")
    amass_bin = resolve_tool_binary("amass")

    if subfinder_bin:
        try:
            proc = subprocess.run(
                [subfinder_bin, "-silent", "-d", domain],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            for line in proc.stdout.splitlines():
                value = line.strip().lower()
                if value:
                    discovered.add(value)
            tool_logs.append({"tool": "subfinder", "return_code": proc.returncode, "items": len(discovered), "binary": subfinder_bin})
        except Exception as e:
            tool_logs.append({"tool": "subfinder", "return_code": "error", "items": 0, "error": str(e), "binary": subfinder_bin})
    else:
        tool_logs.append({"tool": "subfinder", "return_code": "missing", "items": 0})

    if amass_bin:
        try:
            proc = subprocess.run(
                [amass_bin, "enum", "-passive", "-d", domain],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            start_count = len(discovered)
            for line in proc.stdout.splitlines():
                value = line.strip().lower()
                if value and "." in value:
                    discovered.add(value)
            tool_logs.append({"tool": "amass", "return_code": proc.returncode, "items": len(discovered) - start_count, "binary": amass_bin})
        except Exception as e:
            tool_logs.append({"tool": "amass", "return_code": "error", "items": 0, "error": str(e), "binary": amass_bin})
    else:
        tool_logs.append({"tool": "amass", "return_code": "missing", "items": 0})

    return sorted(discovered), tool_logs
