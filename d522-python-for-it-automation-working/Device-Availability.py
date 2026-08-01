#!/usr/bin/env python3
"""
Device-Monitor.py

WGU D522 - Task 3

Step 1: Reads network_devices.csv into a structured inventory of
NetworkDevice objects.

Step 2: Checks every device that has a static management IP for ICMP
availability, and emails stakeholders the "Device Unavailable
Notification" template (Task 2 Email Templates) whenever a device
transitions from up to down.

Designed to be run as a single pass on a schedule (e.g. a cron job every
5 minutes), not as a long-running process. Because each run is a fresh
process, device up/down status is persisted between runs in
device_status_state.json so a device that is already known to be down
does not trigger a duplicate email on every scheduled run -- only the
up -> down transition sends a notification.

Self-contained: no command-line arguments or interactive input needed.
Expects network_devices.csv to sit next to this script.

Usage (run manually, or from cron):
    python3 Device-Monitor.py

Example crontab entry (checks every 5 minutes):
    */5 * * * * /usr/bin/python3 /path/to/Device-Monitor.py >> /var/log/device_monitor.log 2>&1
"""

import csv
import json
import logging
import smtplib
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"
STATE_FILE = SCRIPT_DIR / "device_status_state.json"

REQUIRED_COLUMNS = {
    "Device ID", "Device Name", "Device Address", "Subnet Mask",
    "Location", "Access Port", "OS", "Username", "Password",
}

# Address values meaning "this device has no fixed management IP" (DHCP
# clients, switches with no in-band management address) rather than a
# real, pingable/SSH-able host.
NON_ROUTABLE_ADDRESS_VALUES = {"dhcp", "none", ""}

# TODO: replace with the real stakeholder distribution list before this
# is used outside the lab.
STAKEHOLDER_EMAILS = ["changeme@example.com"]

SENDER_EMAIL = "network-monitor@lab.local"

# Per the lab spec, the SMTP relay must be reached by its DNS name (this
# is resolved using whatever resolver the OS is configured with -- in
# this lab, that means DNS1/DNS2). The CSV's "SMTP" device IP is kept
# only as a fallback in case DNS resolution fails.
SMTP_HOSTNAME = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
SMTP_TIMEOUT = 10  # seconds

PING_COUNT = 1
PING_TIMEOUT = 2  # seconds per ping attempt

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
        """True if this device has a real, fixed IP address to monitor."""
        return self.address.strip().lower() not in NON_ROUTABLE_ADDRESS_VALUES

    @property
    def is_dns_server(self) -> bool:
        """True if this device's name identifies it as a DNS server."""
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
    """
    Read network_devices.csv and return a list of NetworkDevice objects,
    one per row, in file order.

    Handles either comma- or tab-delimited exports automatically, and
    trims stray whitespace from every field (the source file has a
    trailing space on some Location values, e.g. "Services ").

    Raises:
        FileNotFoundError: csv_path does not exist.
        ValueError: the CSV is missing a required column.
    """
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
        except csv.Error:
            dialect = csv.excel  # fall back to standard comma-delimited CSV

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
# Availability check
# ---------------------------------------------------------------------------

def ping_device(address: str, count: int = PING_COUNT, timeout: int = PING_TIMEOUT) -> bool:
    """
    Return True if `address` responds to an ICMP ping, False otherwise
    (including if the ping command itself fails to run).
    """
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError) as exc:
        log.error("Could not run ping against %s: %s", address, exc)
        return False


# ---------------------------------------------------------------------------
# Email (Task 2 "Device Unavailable Notification" template)
# ---------------------------------------------------------------------------

def build_unavailable_email(device: NetworkDevice, timestamp: str) -> Tuple[str, str]:
    """
    Return (subject, body) for the device using the exact "Device
    Unavailable Notification" template from the Task 2 Email Templates
    document.
    """
    subject = f"Network Device Unavailable: {device.name} ({device.address})"
    body = (
        "Dear Network Administrator,\n\n"
        "This is an automated notification that the following network device is currently unavailable:\n\n"
        f"Device Name: {device.name}\n"
        f"IP Address: {device.address}\n"
        f"Last Checked: {timestamp}\n\n"
        "Please investigate this issue at your earliest convenience.\n\n"
        "Best regards, \n"
        "Network Monitoring System\n"
    )
    return subject, body


def send_email(subject: str, body: str, to_addrs: List[str], smtp_hosts: List[str], smtp_port: int = SMTP_PORT) -> None:
    """
    Send a plain-text email via an unauthenticated SMTP relay, trying
    each host in `smtp_hosts` in order (e.g. the lab's DNS hostname
    first, then a raw IP fallback) until one connects successfully.

    Raises the last smtplib.SMTPException/OSError encountered if every
    candidate host fails; callers decide how to handle that.
    """
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
# Persisted status state (so cron runs don't re-alert every 5 minutes)
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    """Return the saved {device_name: "up"|"down"} map, or {} if none exists."""
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read state file %s (%s); starting with empty state.", path, exc)
        return {}


def save_state(path: Path, state: dict) -> None:
    """Persist the {device_name: "up"|"down"} map to disk as JSON."""
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_smtp_targets(devices: List[NetworkDevice]) -> List[str]:
    """
    Return an ordered list of SMTP host candidates: the lab's canonical
    hostname (SMTP_HOSTNAME) first -- resolved via DNS1/DNS2 -- with the
    CSV's "SMTP" device IP appended as a fallback in case DNS resolution
    fails.
    """
    targets = [SMTP_HOSTNAME]
    for device in devices:
        if device.name.strip().upper() == "SMTP" and device.has_static_address:
            if device.address not in targets:
                targets.append(device.address)
            break
    return targets


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """
    Load the device inventory, then check every monitorable device's
    availability and email stakeholders about any device that just
    transitioned from up to down.
    """
    try:
        devices = load_devices()
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    log.info("Loaded %d device(s) from %s", len(devices), CSV_PATH)

    monitorable = [d for d in devices if d.has_static_address]
    skipped = [d for d in devices if not d.has_static_address]

    print(f"\n{'Device Name':<12} {'Address':<16} {'Location':<12} {'Monitorable':<15}")
    print("-" * 57)
    for d in devices:
        status = "yes" if d.has_static_address else "no (DHCP/none)"
        print(f"{d.name:<12} {d.address:<16} {d.location:<12} {status:<15}")

    log.info("%d device(s) have a static address and can be monitored.", len(monitorable))
    log.info(
        "%d device(s) skipped (DHCP or no management address): %s",
        len(skipped),
        ", ".join(d.name for d in skipped) if skipped else "none",
    )

    smtp_targets = get_smtp_targets(devices)
    previous_state = load_state(STATE_FILE)
    updated_state = dict(previous_state)

    log.info("Checking %d device(s) for availability...", len(monitorable))

    for device in monitorable:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_up = ping_device(device.address)
        previous_status = previous_state.get(device.name)

        if is_up:
            updated_state[device.name] = "up"
            if previous_status == "down":
                log.info("%s (%s) has recovered.", device.name, device.address)
            else:
                log.info("%s (%s) is up.", device.name, device.address)
            continue

        # Device is down.
        updated_state[device.name] = "down"
        log.warning("%s (%s) is unreachable.", device.name, device.address)

        if previous_status == "down":
            log.info("%s was already down as of the last check; not re-sending notification.", device.name)
            continue

        subject, body = build_unavailable_email(device, timestamp)
        try:
            send_email(subject, body, STAKEHOLDER_EMAILS, smtp_targets)
            log.info("Sent unavailable-device notification for %s to %s", device.name, ", ".join(STAKEHOLDER_EMAILS))
        except (smtplib.SMTPException, OSError) as exc:
            log.error("Failed to send notification email for %s: %s", device.name, exc)

    save_state(STATE_FILE, updated_state)
    log.info("Availability check complete.")


if __name__ == "__main__":
    main()