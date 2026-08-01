#!/usr/bin/env python3
"""
device_monitor.py

WGU D522 - Task 3, Step 1

Reads network_devices.csv into a structured, reusable inventory of
NetworkDevice objects. This module is the foundation that later steps
of this task (availability monitoring, DNS configuration checks, and
automated email response) will build on and import from.

Self-contained: no command-line arguments or interactive input needed.
Expects network_devices.csv to sit next to this script.

Usage:
    python3 device_monitor.py
"""

import csv
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"

REQUIRED_COLUMNS = {
    "Device ID", "Device Name", "Device Address", "Subnet Mask",
    "Location", "Access Port", "OS", "Username", "Password",
}

# Address values meaning "this device has no fixed management IP" (DHCP
# clients, switches with no in-band management address) rather than a
# real, pingable/SSH-able host.
NON_ROUTABLE_ADDRESS_VALUES = {"dhcp", "none", ""}

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
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Load the device inventory and print a readable summary."""
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


if __name__ == "__main__":
    main()