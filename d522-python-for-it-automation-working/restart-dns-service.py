#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "bind9"

# Directory containing this script
SCRIPT_DIR = Path(__file__).resolve().parent
CONNECT_SCRIPT = SCRIPT_DIR / "connect-to-internal-DNSserver.py"


def run_command(command):
    """
    Run a command and return its stdout.
    Raises RuntimeError if the command fails.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(e.stdout.strip())
        print(e.stderr.strip())
        raise RuntimeError(f"Command failed: {' '.join(command)}") from e


def is_service_running(service_name):
    output = run_command(["systemctl", "is-active", service_name])
    return output == "active"


def restart_dns_service():
    print("Connecting using connect-to-internal-DNSserver.py...")
    run_command(["python3", str(CONNECT_SCRIPT)])

    print(f"Restarting {SERVICE_NAME}...")
    run_command(["sudo", "systemctl", "restart", SERVICE_NAME])

    if is_service_running(SERVICE_NAME):
        print(f"{SERVICE_NAME} restarted successfully and is running.")
    else:
        raise RuntimeError(f"{SERVICE_NAME} restart failed: service is not running.")


if __name__ == "__main__":
    try:
        restart_dns_service()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)