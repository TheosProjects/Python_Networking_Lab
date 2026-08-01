#!/usr/bin/env python3
"""Connect to an internal DNS server and test DNS resolution."""

import argparse
import csv
import re
import socket
import subprocess
import sys

try:
    import paramiko
except ImportError:
    paramiko = None


DEFAULT_CSV_PATH = "/home/student/d522/d522-python-for-it-automation/network_devices.csv"
DNS_SERVICE_NAME = "bind9"   # Debian package name for BIND; use "named" if running unbound/named directly
DEFAULT_SSH_PORT = 22


def read_dns_servers(file_path: str) -> list[tuple[str, int, str, str]]:
    """Read DNS server entries from the CSV.

    Returns a list of (address, dns_port, username, password) tuples.
    """
    servers: list[tuple[str, int, str, str]] = []
    try:
        with open(file_path, mode="r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                device_name = (row.get("Device Name") or "").strip()
                device_address = (row.get("Device Address") or "").strip()
                access_port = (row.get("Access Port") or "").strip()
                username = (row.get("Username") or "").strip()
                password = (row.get("Password") or "").strip()

                if not device_name.startswith("DNS"):
                    continue

                if not device_address:
                    continue

                try:
                    port = int(access_port)
                except ValueError:
                    port = 53

                servers.append((device_address, port, username, password))
    except FileNotFoundError:
        print(f"FAILED: CSV file '{file_path}' was not found.")
    except Exception as error:
        print(f"FAILED: Could not read CSV file '{file_path}': {error}")
    return servers


def check_tcp_connectivity(server: str, port: int = 53, timeout: float = 3.0) -> bool:
    """Return True if TCP connection to DNS server:port succeeds."""
    try:
        with socket.create_connection((server, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_connect_dns1(
    host: str,
    username: str,
    password: str,
    ssh_port: int = DEFAULT_SSH_PORT,
    timeout: float = 10.0,
    commands: list[str] | None = None,
) -> bool:
    """Open an SSH session to DNS1 and optionally run a list of commands.

    Args:
        host:      IP address of DNS1 (10.10.10.10).
        username:  SSH username from the CSV (ubuntu).
        password:  SSH password from the CSV (ubuntu).
        ssh_port:  SSH port to connect on (default 22; the CSV port 53 is the
                   GNS3 console/DNS service port, not SSH).
        timeout:   Socket-level connection timeout in seconds.
        commands:  Optional list of shell commands to execute after connecting.
                   Each command's stdout/stderr is printed.  If None, the
                   function just verifies the connection and exits cleanly.

    Returns:
        True on successful connection (and command execution, if requested).
        False on any error.
    """
    if paramiko is None:
        print("FAILED: paramiko is not installed. Run: pip install paramiko")
        return False

    client = paramiko.SSHClient()
    # Automatically accept the host key on first connection.
    # In a production/hardened environment replace this with a known_hosts check:
    #   client.load_system_host_keys()
    #   client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"SSH: connecting to {host}:{ssh_port} as {username}…")
    try:
        client.connect(
            hostname=host,
            port=ssh_port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,       # Don't try the SSH agent
            look_for_keys=False,     # Password-only; no key files
        )
    except paramiko.AuthenticationException:
        print(f"FAILED: SSH authentication rejected for user '{username}' on {host}:{ssh_port}.")
        return False
    except paramiko.SSHException as err:
        print(f"FAILED: SSH negotiation error connecting to {host}:{ssh_port}: {err}")
        return False
    except OSError as err:
        print(f"FAILED: Network error connecting to {host}:{ssh_port}: {err}")
        return False

    print(f"OK: SSH session established to DNS1 ({host}:{ssh_port}).")

    if not commands:
        client.close()
        return True

    # Execute each command and stream its output.
    all_ok = True
    for cmd in commands:
        print(f"\n  $ {cmd}")
        try:
            _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            exit_status = stdout.channel.recv_exit_status()  # Block until done

            out = stdout.read().decode(errors="replace").strip()
            err_text = stderr.read().decode(errors="replace").strip()

            if out:
                for line in out.splitlines():
                    print(f"    {line}")
            if err_text:
                for line in err_text.splitlines():
                    print(f"    STDERR: {line}")

            if exit_status != 0:
                print(f"    WARNING: command exited with status {exit_status}")
                all_ok = False

        except paramiko.SSHException as err:
            print(f"    FAILED: Error executing command: {err}")
            all_ok = False

    client.close()
    print("\nSSH: session closed.")
    return all_ok


def get_dns_service_status(service_name: str = DNS_SERVICE_NAME) -> str:
    """Return the systemd active state of the DNS service on Debian.

    Returns one of the systemctl ActiveState strings: 'active', 'inactive',
    'activating', 'deactivating', 'failed', or 'UNKNOWN' on error.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        # is-active prints exactly one word: active / inactive / failed / etc.
        state = result.stdout.strip()
        return state if state else "UNKNOWN"
    except OSError:
        return "UNKNOWN"


def restart_dns_service(service_name: str = DNS_SERVICE_NAME) -> bool:
    """Restart the DNS service via systemctl after verifying it is active.

    Requires that the script is run as root or via sudo, since restarting
    system services on Debian requires elevated privileges.
    """
    service_status = get_dns_service_status(service_name)
    print(f"DNS service status: {service_status}")
    if service_status != "active":
        print(f"FAILED: '{service_name}' is not active (state: {service_status}), so it will not be restarted.")
        return False

    result = subprocess.run(
        ["systemctl", "restart", service_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip()
        print(f"FAILED: Could not restart '{service_name}': {err}")
        return False

    print(f"OK: '{service_name}' restarted successfully.")
    return True


def resolve_with_server(server: str, hostname: str) -> str:
    """Resolve hostname by querying the specified DNS server directly."""
    try:
        result = subprocess.run(
            ["nslookup", hostname, server],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise socket.gaierror(result.stderr.strip() or result.stdout.strip() or "nslookup failed")

        for line in result.stdout.splitlines():
            line = line.strip()
            if line.lower().startswith("address:"):
                match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                if match:
                    return match.group(0)

        raise socket.gaierror("DNS response did not include an address")
    except FileNotFoundError:
        # Fallback for environments without nslookup.
        return socket.gethostbyname(hostname)


def main() -> int:
    parser = argparse.ArgumentParser(description="Connect to internal DNS server and test name resolution.")
    parser.add_argument("--csv-path", default=DEFAULT_CSV_PATH, help="Path to the CSV file containing DNS server data")
    parser.add_argument("--server", default=None, help="Optional DNS server hostname or IP to check directly")
    parser.add_argument("--port", type=int, default=None, help="Optional TCP port to use when --server is provided")
    parser.add_argument("--host", default="ns1.d522.wgu.internal", help="Hostname to resolve (default: ns1.d522.wgu.internal)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds")
    parser.add_argument("--restart-service", action="store_true", help="Restart the DNS service via systemctl after verifying it is active (requires root/sudo)")
    parser.add_argument("--ssh", action="store_true", help="Open an SSH session to DNS1 after the connectivity check")
    parser.add_argument("--ssh-port", type=int, default=DEFAULT_SSH_PORT, help=f"SSH port on DNS1 (default: {DEFAULT_SSH_PORT})")
    parser.add_argument("--ssh-command", action="append", dest="ssh_commands", metavar="CMD",
                        help="Command to run over SSH after connecting (repeatable). "
                             "If omitted, the session opens and closes without running anything.")
    args = parser.parse_args()

    if args.restart_service and not restart_dns_service():
        return 1

    # ── Resolve the server list ──────────────────────────────────────────────
    servers_to_check: list[tuple[str, int, str, str]]
    if args.server:
        servers_to_check = [(args.server, args.port or 53, "ubuntu", "ubuntu")]
    else:
        servers_to_check = read_dns_servers(args.csv_path)

    servers_to_check = [(s, p, u, pw) for s, p, u, pw in servers_to_check if s]
    if not servers_to_check:
        print("FAILED: No DNS server values were found in the CSV file.")
        return 1

    server, dns_port, username, password = servers_to_check[0]

    # ── DNS resolution check (existing behaviour) ────────────────────────────
    print(f"Testing DNS server {server} by resolving {args.host}…")
    try:
        ip = resolve_with_server(server, args.host)
        print(f"OK: {args.host} resolved to {ip}")
    except socket.gaierror as err:
        print(f"FAILED: DNS resolution error: {err}")
        return 1

    # ── Optional SSH connection ──────────────────────────────────────────────
    if True:
        ok = ssh_connect_dns1(
            host=server,
            username=username,
            password=password,
            ssh_port=args.ssh_port,
            timeout=args.timeout,
            commands=args.ssh_commands,  # None if flag not provided → just connect
        )
        if not ok:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())