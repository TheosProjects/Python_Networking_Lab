#!/usr/bin/env python3
"""
ticket_creator.py

WGU D522 - Task 3, Step 3

Checks every device in network_devices.csv that has a static management
IP for ICMP availability, and automatically opens a ticket via the
ticketing web service's REST API for each device that is unavailable,
indicating the issue type and which device is affected.

This script is fully self-contained (its own CSV parsing and its own
ping check) so it can run independently of Device-Monitor.py on its own
schedule.

Designed to be run as a single pass on a schedule (e.g. a cron job every
5 minutes), not as a long-running process. Because each run is a fresh
process, device up/down status is persisted between runs in
device_ticket_state.json so a device that is already known to be down
does not get a duplicate ticket opened on every scheduled run -- only
the up -> down transition opens a new ticket.

Self-contained: no command-line arguments or interactive input needed.
Expects network_devices.csv to sit next to this script.

Usage (run manually, or from cron):
    python3 ticket_creator.py

Example crontab entry (checks every 5 minutes):
    */5 * * * * /usr/bin/python3 /path/to/ticket_creator.py >> /var/log/ticket_creator.log 2>&1
"""

import csv
import json
import logging
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"
TICKET_STATE_FILE = SCRIPT_DIR / "device_ticket_state.json"

REQUIRED_COLUMNS = {
    "Device ID", "Device Name", "Device Address", "Subnet Mask",
    "Location", "Access Port", "OS", "Username", "Password",
}

# Address values meaning "this device has no fixed management IP" (DHCP
# clients, switches with no in-band management address) rather than a
# real, pingable host.
NON_ROUTABLE_ADDRESS_VALUES = {"dhcp", "none", ""}

PING_COUNT = 1
PING_TIMEOUT = 2  # seconds per ping attempt

# Per the lab spec, the ticketing web service is reached by its DNS name
# (resolved via DNS1/DNS2). The CSV's "API" device IP is kept only as a
# fallback in case DNS resolution fails.
API_HOSTNAME = "api.d522.wgu.internal"
API_PORT = 5000
TICKET_ENDPOINT_PATH = "/api/tickets"
API_TIMEOUT = 10  # seconds

# TODO: replace with the real bearer token from the course docs before
# running this against the live ticketing service.
API_BEARER_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"

ISSUE_TYPE_UNAVAILABLE = "Device Unavailable"

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
    trims stray whitespace from every field.

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
# Ticketing web service
# ---------------------------------------------------------------------------

def get_api_targets(devices: List[NetworkDevice]) -> List[str]:
    """
    Return an ordered list of ticketing-API host candidates: the lab's
    canonical hostname (API_HOSTNAME) first -- resolved via DNS1/DNS2 --
    with the CSV's "API" device IP appended as a fallback in case DNS
    resolution fails.
    """
    targets = [API_HOSTNAME]
    for device in devices:
        if device.name.strip().upper() == "API" and device.has_static_address:
            if device.address not in targets:
                targets.append(device.address)
            break
    return targets


def build_ticket_payload(device: NetworkDevice, timestamp: str) -> dict:
    """
    Build the JSON body describing a ticket for an unavailable device,
    naming both the issue type and the affected device.
    """
    return {
        "issue_type": ISSUE_TYPE_UNAVAILABLE,
        "device_name": device.name,
        "ip_address": device.address,
        "location": device.location,
        "description": (
            f"Automated monitoring detected that device '{device.name}' "
            f"({device.address}) is unreachable via ICMP ping."
        ),
        "detected_at": timestamp,
    }


def create_ticket(payload: dict, api_targets: List[str]) -> dict:
    """
    POST the ticket payload to TICKET_ENDPOINT_PATH, trying each host in
    api_targets in order (e.g. the lab's DNS hostname first, then a raw
    IP fallback) until one succeeds.

    Returns the parsed JSON response body on success.
    Raises urllib.error.URLError/HTTPError if every candidate host fails.
    """
    if not api_targets:
        raise ValueError("api_targets must contain at least one host to try")

    body = json.dumps(payload).encode("utf-8")
    last_exc = None

    for host in api_targets:
        url = f"http://{host}:{API_PORT}{TICKET_ENDPOINT_PATH}"
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
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
            # The server responded, but rejected the request. Log the
            # response body -- it almost always contains the API's
            # validation error message (e.g. which field was missing or
            # malformed), which is far more useful than the bare status
            # code for figuring out what to fix.
            error_body = exc.read().decode("utf-8", errors="replace")
            log.warning(
                "Ticketing API at %s rejected the request (HTTP %s): %s",
                url, exc.code, error_body,
            )
            last_exc = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            log.warning("Could not reach ticketing API at %s: %s", url, exc)
            last_exc = exc

    raise last_exc


# ---------------------------------------------------------------------------
# Persisted status state (so cron runs don't open a duplicate ticket
# every 5 minutes for the same ongoing outage)
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
# Entry point
# ---------------------------------------------------------------------------

def main():
    try:
        devices = load_devices()
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    api_targets = get_api_targets(devices)
    previous_state = load_state(TICKET_STATE_FILE)
    updated_state = dict(previous_state)

    monitorable = [d for d in devices if d.has_static_address]
    log.info("Checking %d device(s) for availability...", len(monitorable))

    for device in monitorable:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_up = ping_device(device.address)
        previous_status = previous_state.get(device.name)

        if is_up:
            updated_state[device.name] = "up"
            log.info("%s (%s) is up.", device.name, device.address)
            continue

        # Device is down.
        updated_state[device.name] = "down"
        log.warning("%s (%s) is unreachable.", device.name, device.address)

        if previous_status == "down":
            log.info("%s already has an open ticket from a previous check; not creating a duplicate.", device.name)
            continue

        payload = build_ticket_payload(device, timestamp)
        try:
            response = create_ticket(payload, api_targets)
            ticket_id = response.get("id") or response.get("ticket_id") or "unknown"
            log.info("Ticket created for %s (ticket ID: %s)", device.name, ticket_id)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            log.error("Failed to create ticket for %s: %s", device.name, exc)

    save_state(TICKET_STATE_FILE, updated_state)
    log.info("Ticket check complete.")


if __name__ == "__main__":
    main()