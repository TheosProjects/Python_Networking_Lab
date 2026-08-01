#!/usr/bin/env python3
"""
dns_monitor.py

WGU D522 - Task 3, Step 4

For every monitorable device in network_devices.csv, queries DNS1 and
DNS2 directly (not the OS resolver) for that device's internal hostname
(<device-name-lowercase>.d522.wgu.internal) and compares the answer
against the static IP address recorded for that device in the CSV.

When a DNS server's answer doesn't match the expected IP:
    1. Emails stakeholders using the exact "DNS Setting Altered
       Notification" template from the Task 2 Email Templates document.
    2. Opens a ticket for the issue via the ticketing web service.
    3. SSHes into the affected DNS server, corrects the A record in the
       BIND zone file back to the expected IP, bumps the zone's SOA
       serial, and reloads BIND (rndc reload).
    4. Marks the ticket resolved via the ticketing web service.

This script is fully self-contained (own CSV parsing, own SSH/zone-file
logic, own ticketing/email logic) so it can run independently of
Device-Monitor.py and ticket_creator.py on its own schedule.

Self-contained: no command-line arguments or interactive input needed.
Expects network_devices.csv to sit next to this script.

Requires:
    paramiko    (pip3 install paramiko --break-system-packages)
    dig         (Debian/Ubuntu: apt install dnsutils / bind9-dnsutils)

Usage (run manually, or from cron):
    python3 dns_monitor.py

Example crontab entry (checks every 5 minutes):
    */5 * * * * /usr/bin/python3 /path/to/dns_monitor.py >> /var/log/dns_monitor.log 2>&1

NOTE ON ASSUMPTIONS:
- The exact ticket-update schema/endpoint (PATCH /api/tickets/{id} with
  {"status": "resolved"}) was not specified in the course docs, the same
  way the ticket-creation schema wasn't. If the ticketing API rejects
  this with an HTTP error, the error response body is logged -- check
  that log line and adjust build_dns_ticket_payload()/update_ticket_resolved()
  to match.
- The Task 2 Email Templates document also includes a "DNS Setting
  Corrected Notification" template that this script's requirements
  (as given) do not ask it to send. If you want that email sent too
  once the correction succeeds, say so and it can be added.
"""

import csv
import json
import logging
import re
import shlex
import smtplib
import subprocess
import sys
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional, Tuple

import paramiko

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"

REQUIRED_COLUMNS = {
    "Device ID", "Device Name", "Device Address", "Subnet Mask",
    "Location", "Access Port", "OS", "Username", "Password",
}

NON_ROUTABLE_ADDRESS_VALUES = {"dhcp", "none", ""}

# Internal DNS domain used in this lab. Every monitorable device is
# expected to have an A record at <device-name-lowercase>.DOMAIN_SUFFIX.
DOMAIN_SUFFIX = "d522.wgu.internal"

DIG_TIMEOUT = 5  # seconds

NAMED_CONF_LOCAL_PATH = "/etc/bind/named.conf.local"
BIND_ZONE_DIR = "/etc/bind"
SSH_CONNECT_TIMEOUT = 10  # seconds

# TODO: replace with the real stakeholder distribution list before this
# is used outside the lab.
STAKEHOLDER_EMAILS = ["changeme@example.com"]

SENDER_EMAIL = "network-monitor@lab.local"
SMTP_HOSTNAME = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
SMTP_TIMEOUT = 10  # seconds

API_HOSTNAME = "api.d522.wgu.internal"
API_PORT = 5000
TICKET_ENDPOINT_PATH = "/api/tickets"
API_TIMEOUT = 10  # seconds

# TODO: replace if this token is rotated.
API_BEARER_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"

ISSUE_TYPE_DNS_ALTERED = "DNS Setting Altered"

# Devices confirmed to intentionally have no A record in the zone (e.g.
# infrastructure devices that aren't meant to be resolvable by name).
# Their "no record found" case is expected and logged at INFO level
# rather than as a WARNING. Any other device with no record is still
# flagged as a warning, since that's likely a real gap in the zone file.
NO_DNS_RECORD_EXPECTED = {"DNS1", "DNS2", "ROUTER1"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class NetworkDevice:
    """One row of network_devices.csv, normalized into a typed object."""

    device_id: str
    name: str
    address: str
    subnet_mask: str
    location: str
    access_port: str
    os: str
    username: str
    password: str

    @property
    def has_static_address(self) -> bool:
        return self.address.strip().lower() not in NON_ROUTABLE_ADDRESS_VALUES

    @property
    def is_dns_server(self) -> bool:
        return self.name.strip().upper().startswith("DNS")

    def __repr__(self) -> str:
        return (
            f"NetworkDevice(id={self.device_id}, name={self.name!r}, "
            f"address={self.address!r}, location={self.location!r})"
        )


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def load_devices(csv_path: Path = CSV_PATH) -> List[NetworkDevice]:
    """Read network_devices.csv into a list of NetworkDevice objects."""
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing_columns:
            raise ValueError(f"CSV is missing required column(s): {', '.join(sorted(missing_columns))}")

        devices = [
            NetworkDevice(
                device_id=row["Device ID"].strip(),
                name=row["Device Name"].strip(),
                address=row["Device Address"].strip(),
                subnet_mask=row["Subnet Mask"].strip(),
                location=row["Location"].strip(),
                access_port=row["Access Port"].strip(),
                os=row["OS"].strip(),
                username=row["Username"].strip(),
                password=row["Password"].strip(),
            )
            for row in reader
        ]

    return devices


# ---------------------------------------------------------------------------
# DNS querying
# ---------------------------------------------------------------------------

_IPV4_PATTERN = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def expected_hostname_for(device: NetworkDevice) -> str:
    """The internal hostname this device is expected to be reachable at."""
    return f"{device.name.strip().lower()}.{DOMAIN_SUFFIX}"


def query_dns_record(dns_server_ip: str, hostname: str, timeout: int = DIG_TIMEOUT) -> Optional[str]:
    """
    Query `dns_server_ip` directly (bypassing the OS resolver) for the A
    record of `hostname`. Returns the first IPv4 address in the answer,
    or None if there was no answer / a CNAME with no resolvable IP / the
    query failed outright.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", f"@{dns_server_ip}", hostname, "A"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.error("Could not run dig against %s for %s: %s", dns_server_ip, hostname, exc)
        return None

    for line in result.stdout.splitlines():
        line = line.strip()
        if _IPV4_PATTERN.match(line):
            return line
    return None


# ---------------------------------------------------------------------------
# SSH / zone-file correction
# ---------------------------------------------------------------------------

ZONE_BLOCK_PATTERN = re.compile(r'zone\s+"([^"]+)"\s*\{([^}]*)\}\s*;', re.DOTALL)
ZONE_FILE_STATEMENT_PATTERN = re.compile(r'file\s+"([^"]+)"')
# Matches lines like: "api   IN   A   10.10.10.200" (TTL and "IN" both optional).
ZONE_A_RECORD_PATTERN = re.compile(
    r'^(?P<owner>\S+)\s+(?:\d+\s+)?(?:IN\s+)?A\b\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)
SERIAL_COMMENT_PATTERN = re.compile(r'(?P<serial>\d+)(\s*;\s*[Ss]erial)')


def connect_ssh(device: NetworkDevice) -> paramiko.SSHClient:
    """Open an SSH connection to a device, returning a connected SSHClient."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device.address,
            username=device.username,
            password=device.password,
            timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
    except (paramiko.AuthenticationException, paramiko.SSHException, OSError) as exc:
        raise ConnectionError(f"Could not SSH into {device.name} ({device.address}): {exc}") from exc
    return client


def read_remote_file(ssh_client: paramiko.SSHClient, remote_path: str) -> Optional[str]:
    """Return the contents of remote_path via SFTP, or None if it doesn't exist."""
    sftp = ssh_client.open_sftp()
    try:
        with sftp.open(remote_path, "r") as remote_file:
            return remote_file.read().decode("utf-8", errors="replace")
    except (FileNotFoundError, IOError):
        return None
    finally:
        sftp.close()


def _run_sudo_command(ssh_client: paramiko.SSHClient, command: str, sudo_password: str) -> str:
    """
    Run `command` on the remote host with sudo, piping sudo_password via
    stdin (works whether or not the account has NOPASSWD sudo). Raises
    RuntimeError if the command exits non-zero.
    """
    stdin, stdout, stderr = ssh_client.exec_command(f"sudo -S -p '' bash -c {shlex.quote(command)}")
    stdin.write(sudo_password + "\n")
    stdin.flush()
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if exit_code != 0:
        raise RuntimeError(f"Remote command failed (exit {exit_code}): {command}\nstdout: {out}\nstderr: {err}")
    return out


def write_remote_file_as_root(ssh_client: paramiko.SSHClient, remote_path: str, content: str, sudo_password: str) -> None:
    """
    Write `content` to remote_path (which requires root to modify) by
    first uploading it to a temp file the SSH user can write directly,
    then using sudo cp to overwrite the destination in place. Using cp
    (not mv) preserves the destination file's existing ownership and
    permissions (e.g. root:bind, 640), which a straight overwrite via
    mv would lose.
    """
    tmp_path = f"/tmp/.dns_monitor_{uuid.uuid4().hex}"
    sftp = ssh_client.open_sftp()
    try:
        with sftp.open(tmp_path, "w") as f:
            f.write(content)
    finally:
        sftp.close()

    try:
        _run_sudo_command(ssh_client, f"cp {shlex.quote(tmp_path)} {shlex.quote(remote_path)}", sudo_password)
    finally:
        # tmp_path is owned by the SSH user, so no sudo needed to remove it.
        ssh_client.exec_command(f"rm -f {shlex.quote(tmp_path)}")


def find_zone_file_path(ssh_client: paramiko.SSHClient) -> Optional[str]:
    """
    Read named.conf.local and return the absolute path of the zone file
    for DOMAIN_SUFFIX, or None if no matching zone block is found.
    """
    named_conf_local = read_remote_file(ssh_client, NAMED_CONF_LOCAL_PATH)
    if named_conf_local is None:
        return None

    for zone_name, block_body in ZONE_BLOCK_PATTERN.findall(named_conf_local):
        if zone_name.strip().rstrip(".").lower() == DOMAIN_SUFFIX.lower():
            file_match = ZONE_FILE_STATEMENT_PATTERN.search(block_body)
            if file_match:
                path = file_match.group(1)
                return path if path.startswith("/") else f"{BIND_ZONE_DIR.rstrip('/')}/{path}"
    return None


def bump_serial(zone_content: str) -> str:
    """
    Increment the zone's SOA serial number by 1, identified by a
    "; serial" (or "; Serial") trailing comment. If no such comment is
    found, the content is returned unchanged and a warning is logged --
    BIND will still pick up the corrected record on `rndc reload`
    regardless, since reload always re-reads the file from disk.
    """
    match = SERIAL_COMMENT_PATTERN.search(zone_content)
    if not match:
        log.warning("Could not find a '; serial' comment in the zone file; leaving serial unchanged.")
        return zone_content
    new_serial = int(match.group("serial")) + 1
    start, end = match.span("serial")
    return zone_content[:start] + str(new_serial) + zone_content[end:]


def correct_zone_record(
    ssh_client: paramiko.SSHClient,
    zone_file_path: str,
    hostname_label: str,
    expected_ip: str,
    sudo_password: str,
) -> bool:
    """
    Replace the A record for `hostname_label` in the zone file with
    `expected_ip`, bump the SOA serial, write the file back (via sudo),
    and reload BIND. Returns True if a matching record was found and
    corrected, False if no matching record exists in the zone file.
    """
    zone_content = read_remote_file(ssh_client, zone_file_path)
    if zone_content is None:
        raise FileNotFoundError(f"Zone file not found: {zone_file_path}")

    fqdn = f"{hostname_label}.{DOMAIN_SUFFIX}"
    lines = zone_content.splitlines(keepends=True)
    new_lines = []
    corrected = False

    for line in lines:
        stripped = line.rstrip("\n")
        match = None if corrected else ZONE_A_RECORD_PATTERN.match(stripped)
        if match:
            owner = match.group("owner").rstrip(".")
            if owner.lower() in (hostname_label.lower(), fqdn.lower()):
                start, end = match.span("ip")
                new_stripped = stripped[:start] + expected_ip + stripped[end:]
                newline = "\n" if line.endswith("\n") else ""
                new_lines.append(new_stripped + newline)
                corrected = True
                continue
        new_lines.append(line)

    if not corrected:
        return False

    new_content = bump_serial("".join(new_lines))
    write_remote_file_as_root(ssh_client, zone_file_path, new_content, sudo_password)
    _run_sudo_command(ssh_client, "rndc reload", sudo_password)
    return True


# ---------------------------------------------------------------------------
# Email (Task 2 "DNS Setting Altered Notification" template)
# ---------------------------------------------------------------------------

def build_altered_email(device: NetworkDevice, detected_ip: str, expected_ip: str, timestamp: str) -> Tuple[str, str]:
    """Return (subject, body) using the exact Task 2 template wording."""
    subject = f"DNS Configuration Alert: {device.name} ({device.address})"
    body = (
        "Dear Network Administrator,\n\n"
        "This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:\n\n"
        f"Device Name: {device.name}\n"
        f"IP Address: {device.address}\n"
        f"Detected DNS Setting: {detected_ip}\n"
        f"Expected DNS Setting: {expected_ip}\n"
        f"Time Detected: {timestamp}\n\n"
        "The system will attempt to automatically correct this configuration.\n\n"
        "Best regards, \n"
        "Network Monitoring System\n"
    )
    return subject, body


def get_smtp_targets(devices: List[NetworkDevice]) -> List[str]:
    """SMTP host candidates: the lab's DNS hostname first, CSV IP as fallback."""
    targets = [SMTP_HOSTNAME]
    for device in devices:
        if device.name.strip().upper() == "SMTP" and device.has_static_address:
            if device.address not in targets:
                targets.append(device.address)
            break
    return targets


def send_email(subject: str, body: str, to_addrs: List[str], smtp_hosts: List[str], smtp_port: int = SMTP_PORT) -> None:
    """Send a plain-text email, trying each SMTP host candidate in order."""
    if not smtp_hosts:
        raise ValueError("smtp_hosts must contain at least one host to try")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    last_exc = None
    for host in smtp_hosts:
        try:
            with smtplib.SMTP(host, smtp_port, timeout=SMTP_TIMEOUT) as server:
                server.send_message(msg)
            return
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("Could not reach SMTP host %s: %s", host, exc)
            last_exc = exc
    raise last_exc


# ---------------------------------------------------------------------------
# Ticketing web service
# ---------------------------------------------------------------------------

def get_api_targets(devices: List[NetworkDevice]) -> List[str]:
    """Ticketing-API host candidates: the lab's DNS hostname first, CSV IP as fallback."""
    targets = [API_HOSTNAME]
    for device in devices:
        if device.name.strip().upper() == "API" and device.has_static_address:
            if device.address not in targets:
                targets.append(device.address)
            break
    return targets


def _api_request(method: str, path: str, payload: dict, api_targets: List[str]) -> dict:
    """
    Send an HTTP request with a JSON body to the ticketing API, trying
    each host in api_targets in order. Returns the parsed JSON response.
    Raises the last error encountered if every candidate host fails.
    """
    body = json.dumps(payload).encode("utf-8")
    last_exc = None

    for host in api_targets:
        url = f"http://{host}:{API_PORT}{path}"
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {API_BEARER_TOKEN}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
                response_body = response.read().decode("utf-8")
                return json.loads(response_body) if response_body else {}
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            log.warning("Ticketing API at %s rejected the request (HTTP %s): %s", url, exc.code, error_body)
            last_exc = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            log.warning("Could not reach ticketing API at %s: %s", url, exc)
            last_exc = exc

    raise last_exc


def build_dns_ticket_payload(device: NetworkDevice, dns_server: NetworkDevice, detected_ip: str, expected_ip: str, timestamp: str) -> dict:
    """Build the JSON body describing a ticket for a DNS-alteration issue."""
    return {
        "issue_type": ISSUE_TYPE_DNS_ALTERED,
        "device_name": device.name,
        "ip_address": device.address,
        "dns_server": dns_server.name,
        "description": (
            f"DNS record for '{device.name}' ({expected_hostname_for(device)}) resolved to "
            f"{detected_ip} via {dns_server.name} ({dns_server.address}); expected {expected_ip}."
        ),
        "detected_at": timestamp,
    }


def create_ticket(payload: dict, api_targets: List[str]) -> dict:
    """POST a new ticket. Returns the parsed JSON response on success."""
    return _api_request("POST", TICKET_ENDPOINT_PATH, payload, api_targets)


def update_ticket_resolved(ticket_id, api_targets: List[str]) -> dict:
    """
    Mark an existing ticket resolved. Uses PATCH with {"status": "resolved"}
    since the exact update schema wasn't specified in the course docs --
    see the NOTE ON ASSUMPTIONS at the top of this file if this is rejected.
    """
    path = f"{TICKET_ENDPOINT_PATH}/{ticket_id}"
    return _api_request("PATCH", path, {"status": "resolved"}, api_targets)


# ---------------------------------------------------------------------------
# Per-DNS-server handling
# ---------------------------------------------------------------------------

def handle_alterations_on_server(
    dns_server: NetworkDevice,
    alterations: List[Tuple[NetworkDevice, str, str, str]],
    smtp_targets: List[str],
    api_targets: List[str],
) -> None:
    """
    For each (device, hostname, detected_ip, expected_ip) alteration
    found on `dns_server`: email stakeholders, open a ticket, correct
    the zone file, and mark the ticket resolved.
    """
    try:
        ssh_client = connect_ssh(dns_server)
    except ConnectionError as exc:
        log.error(str(exc))
        return

    try:
        zone_file_path = find_zone_file_path(ssh_client)
        if zone_file_path is None:
            log.error(
                "%s: could not find a zone file for '%s' in named.conf.local; cannot auto-correct.",
                dns_server.name, DOMAIN_SUFFIX,
            )
            return

        for device, hostname, detected_ip, expected_ip in alterations:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Step 1: notify stakeholders (Task 2 "DNS Setting Altered Notification").
            subject, body = build_altered_email(device, detected_ip, expected_ip, timestamp)
            try:
                send_email(subject, body, STAKEHOLDER_EMAILS, smtp_targets)
                log.info("Sent DNS-altered notification for %s to %s", device.name, ", ".join(STAKEHOLDER_EMAILS))
            except (smtplib.SMTPException, OSError) as exc:
                log.error("Failed to send DNS-altered notification for %s: %s", device.name, exc)

            # Open a ticket for this DNS issue.
            ticket_id = None
            payload = build_dns_ticket_payload(device, dns_server, detected_ip, expected_ip, timestamp)
            try:
                response = create_ticket(payload, api_targets)
                ticket_id = response.get("id") or response.get("ticket_id")
                log.info("Ticket created for DNS alteration on %s (ticket ID: %s)", device.name, ticket_id)
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                log.error("Failed to create ticket for DNS alteration on %s: %s", device.name, exc)

            # Step 2: correct the DNS setting.
            try:
                corrected = correct_zone_record(ssh_client, zone_file_path, device.name.lower(), expected_ip, dns_server.password)
            except (FileNotFoundError, RuntimeError, OSError) as exc:
                log.error("Failed to correct DNS record for %s on %s: %s", device.name, dns_server.name, exc)
                continue

            if not corrected:
                log.error("%s: no matching A record found in zone file for %s; nothing to correct.", dns_server.name, hostname)
                continue

            log.info("%s: corrected %s's A record to %s and reloaded BIND.", dns_server.name, hostname, expected_ip)

            # Step 3: update the ticket to show the DNS issue has been resolved.
            if ticket_id is not None:
                try:
                    update_ticket_resolved(ticket_id, api_targets)
                    log.info("Ticket %s marked resolved.", ticket_id)
                except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                    log.error("Failed to mark ticket %s resolved: %s", ticket_id, exc)
            else:
                log.warning("No ticket ID available for %s; cannot mark ticket resolved.", device.name)
    finally:
        ssh_client.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    try:
        devices = load_devices()
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    monitorable = [d for d in devices if d.has_static_address]
    dns_servers = [d for d in monitorable if d.is_dns_server]

    if not dns_servers:
        log.error("No DNS server devices found in inventory (expected device names starting with 'DNS').")
        sys.exit(1)

    smtp_targets = get_smtp_targets(devices)
    api_targets = get_api_targets(devices)

    any_alterations = False

    for dns_server in dns_servers:
        alterations = []
        for device in monitorable:
            hostname = expected_hostname_for(device)
            expected_ip = device.address
            detected_ip = query_dns_record(dns_server.address, hostname)

            if detected_ip is None:
                if device.name.strip().upper() in NO_DNS_RECORD_EXPECTED:
                    log.info(
                        "%s: %s has no DNS record, as expected -- skipping.",
                        dns_server.name, hostname,
                    )
                else:
                    log.warning(
                        "%s: could not resolve %s -- skipping (treated as inconclusive, not an alteration).",
                        dns_server.name, hostname,
                    )
                continue

            if detected_ip != expected_ip:
                log.warning(
                    "%s: %s resolves to %s, expected %s -- DNS setting altered.",
                    dns_server.name, hostname, detected_ip, expected_ip,
                )
                alterations.append((device, hostname, detected_ip, expected_ip))
            else:
                log.info("%s: %s correctly resolves to %s.", dns_server.name, hostname, expected_ip)

        if alterations:
            any_alterations = True
            handle_alterations_on_server(dns_server, alterations, smtp_targets, api_targets)

    if not any_alterations:
        log.info("No DNS alterations detected across %d DNS server(s).", len(dns_servers))


if __name__ == "__main__":
    main()