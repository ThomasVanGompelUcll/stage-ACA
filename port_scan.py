"""
Port scanning module using Nmap.

WARNING: This is an active/aggressive scanning tool that may trigger SIEM/IDS alerts.
Only use with explicit authorization on target systems.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _is_working_nmap(binary: str) -> bool:
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def find_nmap() -> str:
    """Locate nmap binary."""
    checked_paths: list[str] = []

    env_candidate = os.getenv("NMAP_PATH", "").strip() or os.getenv("NMAP_EXECUTABLE", "").strip()
    if env_candidate:
        checked_paths.append(env_candidate)
        if _is_working_nmap(env_candidate):
            return env_candidate

    which_candidate = shutil.which("nmap")
    if which_candidate:
        checked_paths.append(which_candidate)
        if _is_working_nmap(which_candidate):
            return which_candidate

    checked_paths.append("nmap")
    if _is_working_nmap("nmap"):
        return "nmap"

    local_app_data = os.getenv("LOCALAPPDATA", "")
    win_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\ProgramData\chocolatey\bin\nmap.exe",
    ]
    if local_app_data:
        win_paths.append(str(Path(local_app_data) / "Programs" / "Nmap" / "nmap.exe"))

    for path in win_paths:
        checked_paths.append(path)
        if Path(path).exists() and _is_working_nmap(path):
            return path

    checked_preview = "\n - ".join(checked_paths[:8])
    raise RuntimeError(
        "Nmap not found. Install from https://nmap.org/download.html or set NMAP_PATH in .env to nmap.exe."
        f"\nChecked:\n - {checked_preview}"
    )


def parse_nmap_output(output: str) -> list[dict[str, Any]]:
    """
    Parse basic nmap text output into structured format.
    This is a simple parser; for production use grepable (-oG) or XML (-oX) output.
    """
    results = []
    lines = output.split("\n")
    current_host = None

    for line in lines:
        line = line.strip()

        # Host line: "Nmap scan report for 1.2.3.4"
        if line.startswith("Nmap scan report for"):
            current_host = line.split("for")[-1].strip()
            if " (" in current_host:
                current_host = current_host.split(" ")[0]
            continue

        # Port line: "22/tcp   open  ssh"
        if "/" in line and ("open" in line or "closed" in line or "filtered" in line):
            parts = line.split()
            if len(parts) >= 3 and current_host:
                port_proto = parts[0]  # "22/tcp"
                state = parts[1]  # "open"
                service = " ".join(parts[2:]) if len(parts) > 2 else ""

                if "/" in port_proto:
                    port, proto = port_proto.split("/")
                    results.append(
                        {
                            "host": current_host,
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                        }
                    )

    return results


def perform_port_scan(
    target: str,
    scan_type: str = "sS",
    ports: str = "--top-ports 1000",
    extra_args: str = "",
) -> dict:
    """
    Run Nmap port scan on target.

    Args:
        target: Host or IP to scan (e.g. "example.com" or "192.168.1.1")
        scan_type: Scan type (sS=SYN, sT=TCP Connect, sU=UDP, etc.)
        ports: Port specification (e.g. "--top-ports 1000", "-p 1-65535", "-p 22,80,443")
        extra_args: Additional nmap arguments

    Returns:
        Dict with scan metadata and open/filtered ports.
    """
    nmap_bin = find_nmap()

    normalized_scan_type = scan_type.strip().lstrip("-") or "sS"

    # Build command
    cmd = [
        nmap_bin,
        f"-{normalized_scan_type}",  # Scan type
        "-v",  # Verbose
        "--reason",  # Show why port is open/closed
        "-sV",  # Service version detection
    ]

    if ports.strip():
        cmd.extend(shlex.split(ports, posix=False))

    if extra_args.strip():
        cmd.extend(shlex.split(extra_args, posix=False))

    cmd.append(target)

    print(f"[*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out after 300 seconds on {target}")

    if result.returncode not in (0, 1):  # 0 = found, 1 = no host up
        raise RuntimeError(f"Nmap error: {result.stderr}")

    output = result.stdout
    parsed_ports = parse_nmap_output(output)

    return {
        "target": target,
        "scan_type": normalized_scan_type,
        "ports_spec": ports,
        "ports_found": len(parsed_ports),
        "open_ports": [p for p in parsed_ports if p["state"] == "open"],
        "filtered_ports": [p for p in parsed_ports if p["state"] == "filtered"],
        "closed_ports": [p for p in parsed_ports if p["state"] == "closed"],
        "all_ports": parsed_ports,
        "raw_output": output,
    }


def main() -> None:
    """CLI interface for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Port scanner using Nmap")
    parser.add_argument("target", help="Target host or IP")
    parser.add_argument(
        "--type", default="sS", help="Scan type (sS=SYN, sT=TCP, sU=UDP, etc.)"
    )
    parser.add_argument(
        "--ports", default="--top-ports 1000", help="Port specification"
    )
    parser.add_argument("--extra", default="", help="Extra nmap arguments")
    args = parser.parse_args()

    result = perform_port_scan(
        args.target, scan_type=args.type, ports=args.ports, extra_args=args.extra
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
