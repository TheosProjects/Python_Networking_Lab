#!/usr/bin/env python3
"""
Connect to each affected device in network_devices.csv and update DNS settings.

Skips:
  - Devices with DHCP addresses (no static IP to connect to)
  - Switches (OpenvSwitch — no SSH, no credentials)
  - The DNS servers themselves (they ARE the DNS source of truth)

For Ubuntu devices, SSHes in and writes /etc/resolv.conf.
For VyOS devices, SSHes in and runs 'set system name-server' CLI commands.
SSH port is read from the Access Port column in the CSV for each device.
"""

import csv
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("FAILED: paramiko is not installed. Run: pip install paramiko")
    sys.exit(1)


"""
Connect to each affected device in network_devices.csv and update DNS settings.

Skips:
  - Devices with DHCP addresses (no static IP to connect to)
  - Switches (OpenvSwitch — no SSH, no credentials)
  - The DNS servers themselves (they ARE the DNS source of truth)

For Ubuntu devices, SSHes in and writes /etc/resolv.conf.
For VyOS devices, SSHes in and runs 'set system name-server' CLI commands.
SSH port is read from the Access Port column in the CSV for each device.
"""

import csv
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("FAILED: paramiko is not installed. Run: pip install paramiko")
    sys.exit(1)


CSV_PATH = Path("/home/student/d522/d522-python-for-it-automation/network_devices.csv")
TIMEOUT  = 10.0

SKIP_OS           = {"openvswitch"}
SKIP_NAMES_PREFIX = ("DNS",)


def load_devices(csv_path: Path) -> list[dict]:
    """Read network_devices.csv and return a list of actionable device dicts."""
    devices = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name        = (row.get("Device Name")   or "").strip()
                address     = (row.get("Device Address") or "").strip()
                username    = (row.get("Username")       or "").strip()
                password    = (row.get("Password")       or "").strip()
                os_type     = (row.get("OS")             or "").strip().lower()

                # Skip switches — no SSH
                if os_type in SKIP_OS:
                    print(f"SKIP [{name}]: OpenvSwitch — no SSH access.")
                    continue

                # Skip DNS servers
                if any(name.startswith(p) for p in SKIP_NAMES_PREFIX):
                    print(f"SKIP [{name}]: DNS server — not updating its own resolver.")
                    continue

                # Skip DHCP devices
                if address.upper() == "DHCP" or not address:
                    print(f"SKIP [{name}]: DHCP address — cannot target for SSH.")
                    continue

                # Skip devices with no credentials
                if not username or username.lower() == "none":
                    print(f"SKIP [{name}]: No credentials available.")
                    continue

                devices.append({
                    "name":     name,
                    "address":  address,
                    "port":     22,
                    "username": username,
                    "password": password,
                    "os":       os_type,
                })
    except FileNotFoundError:
        print(f"FAILED: CSV not found at {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"FAILED: Could not read CSV: {e}")
        sys.exit(1)

    return devices


def load_dns_servers(csv_path: Path) -> list[str]:
    """Extract DNS server IPs from the CSV (rows where Device Name starts with DNS)."""
    dns_ips = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name    = (row.get("Device Name")   or "").strip()
                address = (row.get("Device Address") or "").strip()
                if name.startswith("DNS") and address and address.upper() != "DHCP":
                    dns_ips.append(address)
    except Exception as e:
        print(f"FAILED: Could not read DNS servers from CSV: {e}")
        sys.exit(1)

    if not dns_ips:
        print("FAILED: No DNS server IPs found in CSV.")
        sys.exit(1)

    return dns_ips


def build_resolv_conf(dns_ips: list[str]) -> str:
    """Build /etc/resolv.conf content for Ubuntu devices."""
    lines = ["# Managed by update_dns_settings.py"]
    for ip in dns_ips:
        lines.append(f"nameserver {ip}")
    return "\n".join(lines) + "\n"


def ssh_connect(device: dict) -> paramiko.SSHClient | None:
    """Open and return an SSH connection to the device, or None on failure."""
    name    = device["name"]
    address = device["address"]
    port    = device["port"]
    user    = device["username"]
    pw      = device["password"]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"\n[{name}] Connecting to {address}:{port} as {user}…")
    try:
        client.connect(
            hostname=address,
            port=port,
            username=user,
            password=pw,
            timeout=TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        print(f"[{name}] Connected.")
        return client
    except paramiko.AuthenticationException:
        print(f"[{name}] FAILED: Authentication rejected.")
    except paramiko.SSHException as e:
        print(f"[{name}] FAILED: SSH error: {e}")
    except OSError as e:
        print(f"[{name}] FAILED: Network error: {e}")
    return None


def ssh_run(client: paramiko.SSHClient, cmd: str, name: str) -> tuple[int, str, str]:
    """Run a command over SSH. Returns (exit_status, stdout, stderr)."""
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT)
    exit_status = stdout.channel.recv_exit_status()
    return (
        exit_status,
        stdout.read().decode(errors="replace").strip(),
        stderr.read().decode(errors="replace").strip(),
    )


def update_ubuntu(device: dict, resolv_content: str) -> bool:
    """Write /etc/resolv.conf on an Ubuntu device via SSH."""
    name   = device["name"]
    client = ssh_connect(device)
    if client is None:
        return False

    escaped = resolv_content.replace("'", "'\\''")
    cmd = f"echo '{escaped}' | sudo tee /etc/resolv.conf > /dev/null"

    status, _out, err = ssh_run(client, cmd, name)
    client.close()

    if status != 0:
        print(f"[{name}] FAILED: Could not write /etc/resolv.conf (exit {status}).")
        if err:
            print(f"[{name}] STDERR: {err}")
        return False

    print(f"[{name}] OK: /etc/resolv.conf updated successfully.")
    return True


def update_vyos(device: dict, dns_ips: list[str]) -> bool:
    """Configure name-servers on a VyOS device via SSH CLI."""
    name   = device["name"]
    client = ssh_connect(device)
    if client is None:
        return False

    # VyOS requires entering configure mode, then setting each name-server,
    # then committing and saving — all as sequential interactive commands.
    # We use invoke_shell() for this because exec_command() opens a
    # non-interactive channel that doesn't support the VyOS config CLI.
    try:
        shell = client.invoke_shell()
        time.sleep(1)  # wait for the shell prompt

        commands = ["configure"]
        for ip in dns_ips:
            commands.append(f"set system name-server {ip}")
        commands += ["commit", "save", "exit"]

        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(0.8)  # allow each command to process

        # Drain output
        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode(errors="replace")

        client.close()

        if "Error" in output or "failed" in output.lower():
            print(f"[{name}] FAILED: VyOS returned an error.")
            print(f"[{name}] Output: {output.strip()}")
            return False

        print(f"[{name}] OK: DNS name-servers set and saved successfully.")
        return True

    except paramiko.SSHException as e:
        print(f"[{name}] FAILED: SSH error during VyOS config: {e}")
        client.close()
        return False


def main() -> int:
    print(f"Reading devices from: {CSV_PATH}\n")

    dns_servers = load_dns_servers(CSV_PATH)
    print(f"DNS servers found in CSV: {', '.join(dns_servers)}\n")

    resolv_content = build_resolv_conf(dns_servers)
    print("resolv.conf content that will be written to Ubuntu devices:")
    for line in resolv_content.strip().splitlines():
        print(f"  {line}")
    print()

    devices = load_devices(CSV_PATH)

    if not devices:
        print("No eligible devices to update.")
        return 0

    print(f"Devices to update: {len(devices)}\n")
    print("-" * 50)

    results = {"ok": [], "failed": []}

    for device in devices:
        os_type = device["os"]

        if os_type == "vyos":
            success = update_vyos(device, dns_servers)
        else:
            # Ubuntu and anything else with a standard Linux filesystem
            success = update_ubuntu(device, resolv_content)

        if success:
            results["ok"].append(device["name"])
        else:
            results["failed"].append(device["name"])

    print("\n" + "=" * 50)
    print(f"Done. {len(results['ok'])} succeeded, {len(results['failed'])} failed.")
    if results["ok"]:
        print(f"  Updated: {', '.join(results['ok'])}")
    if results["failed"]:
        print(f"  Failed:  {', '.join(results['failed'])}")

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
TIMEOUT  = 10.0

SKIP_OS           = {"openvswitch"}
SKIP_NAMES_PREFIX = ("DNS",)


def load_devices(csv_path: Path) -> list[dict]:
    """Read network_devices.csv and return a list of actionable device dicts."""
    devices = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name        = (row.get("Device Name")   or "").strip()
                address     = (row.get("Device Address") or "").strip()
                username    = (row.get("Username")       or "").strip()
                password    = (row.get("Password")       or "").strip()
                os_type     = (row.get("OS")             or "").strip().lower()

                # Skip switches — no SSH
                if os_type in SKIP_OS:
                    print(f"SKIP [{name}]: OpenvSwitch — no SSH access.")
                    continue

                # Skip DNS servers
                if any(name.startswith(p) for p in SKIP_NAMES_PREFIX):
                    print(f"SKIP [{name}]: DNS server — not updating its own resolver.")
                    continue

                # Skip DHCP devices
                if address.upper() == "DHCP" or not address:
                    print(f"SKIP [{name}]: DHCP address — cannot target for SSH.")
                    continue

                # Skip devices with no credentials
                if not username or username.lower() == "none":
                    print(f"SKIP [{name}]: No credentials available.")
                    continue

                devices.append({
                    "name":     name,
                    "address":  address,
                    "port":     22,
                    "username": username,
                    "password": password,
                    "os":       os_type,
                })
    except FileNotFoundError:
        print(f"FAILED: CSV not found at {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"FAILED: Could not read CSV: {e}")
        sys.exit(1)

    return devices


def load_dns_servers(csv_path: Path) -> list[str]:
    """Extract DNS server IPs from the CSV (rows where Device Name starts with DNS)."""
    dns_ips = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name    = (row.get("Device Name")   or "").strip()
                address = (row.get("Device Address") or "").strip()
                if name.startswith("DNS") and address and address.upper() != "DHCP":
                    dns_ips.append(address)
    except Exception as e:
        print(f"FAILED: Could not read DNS servers from CSV: {e}")
        sys.exit(1)

    if not dns_ips:
        print("FAILED: No DNS server IPs found in CSV.")
        sys.exit(1)

    return dns_ips


def build_resolv_conf(dns_ips: list[str]) -> str:
    """Build /etc/resolv.conf content for Ubuntu devices."""
    lines = ["# Managed by update_dns_settings.py"]
    for ip in dns_ips:
        lines.append(f"nameserver {ip}")
    return "\n".join(lines) + "\n"


def ssh_connect(device: dict) -> paramiko.SSHClient | None:
    """Open and return an SSH connection to the device, or None on failure."""
    name    = device["name"]
    address = device["address"]
    port    = device["port"]
    user    = device["username"]
    pw      = device["password"]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"\n[{name}] Connecting to {address}:{port} as {user}…")
    try:
        client.connect(
            hostname=address,
            port=port,
            username=user,
            password=pw,
            timeout=TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        print(f"[{name}] Connected.")
        return client
    except paramiko.AuthenticationException:
        print(f"[{name}] FAILED: Authentication rejected.")
    except paramiko.SSHException as e:
        print(f"[{name}] FAILED: SSH error: {e}")
    except OSError as e:
        print(f"[{name}] FAILED: Network error: {e}")
    return None


def ssh_run(client: paramiko.SSHClient, cmd: str, name: str) -> tuple[int, str, str]:
    """Run a command over SSH. Returns (exit_status, stdout, stderr)."""
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT)
    exit_status = stdout.channel.recv_exit_status()
    return (
        exit_status,
        stdout.read().decode(errors="replace").strip(),
        stderr.read().decode(errors="replace").strip(),
    )


def update_ubuntu(device: dict, resolv_content: str) -> bool:
    """Write /etc/resolv.conf on an Ubuntu device via SSH."""
    name   = device["name"]
    client = ssh_connect(device)
    if client is None:
        return False

    escaped = resolv_content.replace("'", "'\\''")
    cmd = f"echo '{escaped}' | sudo tee /etc/resolv.conf > /dev/null"

    status, _out, err = ssh_run(client, cmd, name)
    client.close()

    if status != 0:
        print(f"[{name}] FAILED: Could not write /etc/resolv.conf (exit {status}).")
        if err:
            print(f"[{name}] STDERR: {err}")
        return False

    print(f"[{name}] OK: /etc/resolv.conf updated successfully.")
    return True


def update_vyos(device: dict, dns_ips: list[str]) -> bool:
    """Configure name-servers on a VyOS device via SSH CLI."""
    name   = device["name"]
    client = ssh_connect(device)
    if client is None:
        return False

    # VyOS requires entering configure mode, then setting each name-server,
    # then committing and saving — all as sequential interactive commands.
    # We use invoke_shell() for this because exec_command() opens a
    # non-interactive channel that doesn't support the VyOS config CLI.
    try:
        shell = client.invoke_shell()
        time.sleep(1)  # wait for the shell prompt

        commands = ["configure"]
        for ip in dns_ips:
            commands.append(f"set system name-server {ip}")
        commands += ["commit", "save", "exit"]

        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(0.8)  # allow each command to process

        # Drain output
        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode(errors="replace")

        client.close()

        if "Error" in output or "failed" in output.lower():
            print(f"[{name}] FAILED: VyOS returned an error.")
            print(f"[{name}] Output: {output.strip()}")
            return False

        print(f"[{name}] OK: DNS name-servers set and saved successfully.")
        return True

    except paramiko.SSHException as e:
        print(f"[{name}] FAILED: SSH error during VyOS config: {e}")
        client.close()
        return False


def main() -> int:
    print(f"Reading devices from: {CSV_PATH}\n")

    dns_servers = load_dns_servers(CSV_PATH)
    print(f"DNS servers found in CSV: {', '.join(dns_servers)}\n")

    resolv_content = build_resolv_conf(dns_servers)
    print("resolv.conf content that will be written to Ubuntu devices:")
    for line in resolv_content.strip().splitlines():
        print(f"  {line}")
    print()

    devices = load_devices(CSV_PATH)

    if not devices:
        print("No eligible devices to update.")
        return 0

    print(f"Devices to update: {len(devices)}\n")
    print("-" * 50)

    results = {"ok": [], "failed": []}

    for device in devices:
        os_type = device["os"]

        if os_type == "vyos":
            success = update_vyos(device, dns_servers)
        else:
            # Ubuntu and anything else with a standard Linux filesystem
            success = update_ubuntu(device, resolv_content)

        if success:
            results["ok"].append(device["name"])
        else:
            results["failed"].append(device["name"])

    print("\n" + "=" * 50)
    print(f"Done. {len(results['ok'])} succeeded, {len(results['failed'])} failed.")
    if results["ok"]:
        print(f"  Updated: {', '.join(results['ok'])}")
    if results["failed"]:
        print(f"  Failed:  {', '.join(results['failed'])}")

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())