#!/usr/bin/env python3
"""
dns_status_logger.py

WGU D522 - Task 3, Step 5

For every monitorable device in network_devices.csv, queries DNS1 and
DNS2 directly for that device's internal hostname
(<device-name-lowercase>.d522.wgu.internal) and, if every DNS server
returns the expected IP address (i.e. the record has not been altered),
appends a line to dns_status.log recording the device name, date, and
time it was confirmed correct.

Devices with no DNS record at all (DNS1, DNS2, ROUTER1 -- see
NO_DNS_RECORD_EXPECTED) are skipped, since there's nothing to confirm.
Devices with an altered or unresolvable record are also skipped here --
this script only logs confirmed-correct status; detecting and fixing
alterations is handled by dns_monitor.py.

This script is fully self-contained (its own CSV parsing and its own
DNS querying) so it can run independently of dns_monitor.py on its own
schedule.

Self-contained: no command-line arguments or interactive input needed.
Expects network_devices.csv to sit next to this script.

Usage (run manually, or from cron):
    python3 dns_status_logger.py

Example crontab entry (checks every 5 minutes):
    */5 * * * * /usr/bin/python3 /path/to/dns_status_logger.py >> /var/log/dns_status_logger.log 2>&1

Requires:
    dig    (Debian/Ubuntu: apt install dnsutils / bind9-dnsutils)
"""

import csv
import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"
STATUS_LOG_PATH = SCRIPT_DIR / "dns_status.log"

REQUIRED_COLUMNS = {
    "Device ID", "Device Name", "Device Address", "Subnet Mask",
    "Location", "Access Port", "OS", "Username", "Password",
}

NON_ROUTABLE_ADDRESS_VALUES = {"dhcp", "none", ""}

DOMAIN_SUFFIX = "d522.wgu.internal"
DIG_TIMEOUT = 5  # seconds

# Devices confirmed to intentionally have no A record in the zone.
# There's nothing to confirm as "correct" for these, so they're skipped.
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
    Query `dns_server_ip` directly for the A record of `hostname`.
    Returns the first IPv4 address in the answer, or None if there was
    no answer or the query failed outright.
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
# Status log
# ---------------------------------------------------------------------------

def append_status_log(device_name: str, timestamp: str, log_path: Path = STATUS_LOG_PATH) -> None:
    """
    Append a single line to the DNS status log recording that
    `device_name`'s DNS record was confirmed correct at `timestamp`.
    """
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} - {device_name} - OK\n")


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

    checkable_devices = [d for d in monitorable if d.name.strip().upper() not in NO_DNS_RECORD_EXPECTED]

    confirmed_count = 0

    for device in checkable_devices:
        hostname = expected_hostname_for(device)
        expected_ip = device.address

        results = {}
        for dns_server in dns_servers:
            results[dns_server.name] = query_dns_record(dns_server.address, hostname)

        all_correct = all(ip == expected_ip for ip in results.values())

        if all_correct:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            append_status_log(device.name, timestamp)
            confirmed_count += 1
            log.info("%s: DNS record confirmed correct on all DNS server(s); logged to %s", device.name, STATUS_LOG_PATH)
        else:
            details = ", ".join(f"{name}={ip or 'no answer'}" for name, ip in results.items())
            log.info(
                "%s: DNS record not confirmed correct (expected %s; got %s) -- not logged.",
                device.name, expected_ip, details,
            )

    log.info("Logged %d of %d checkable device(s) as confirmed correct.", confirmed_count, len(checkable_devices))


if __name__ == "__main__":
    main()