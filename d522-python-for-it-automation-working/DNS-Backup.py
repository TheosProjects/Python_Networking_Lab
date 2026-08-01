#!/usr/bin/env python3
"""
dns_backup.py

WGU D522 - Task 2

Creates a local backup of the BIND9 DNS configuration (named.conf.local
plus every zone file it references) pulled live over SSH from DNS1 and
DNS2, using the connection details in network_devices.csv.

Output directory structure produced:

    DNS-Backup/
        Server-1/
            record-config.txt      <- DNS1's named.conf.local + zone files
        Server-2/
            record-config.txt      <- DNS2's named.conf.local + zone files

This script is fully self-contained: it takes no command-line arguments,
no flags, and no interactive input. Just run it:

    python3 dns_backup.py

It expects network_devices.csv to be in the same directory as this
script (see CSV_PATH below). Edit the constants in the Configuration
section if your file layout differs.

Requires:
    paramiko    (pip3 install paramiko --break-system-packages)
"""

import csv
import logging
import re
import sys
from pathlib import Path

import paramiko


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the CSV file and the directory the backup will be written to.
# Both are resolved relative to this script's own location, so the script
# can be run from any working directory without needing any arguments.
SCRIPT_DIR = Path(__file__).resolve().parent
CSV_PATH = SCRIPT_DIR / "network_devices.csv"
OUTPUT_DIR = SCRIPT_DIR / "DNS-Backup"

# Maps a device's "Device Name" column (in network_devices.csv) to the
# backup subdirectory it must be written to, per the task requirements.
DEVICE_NAME_TO_SUBDIR = {
    "DNS1": "Server-1",
    "DNS2": "Server-2",
}

NAMED_CONF_LOCAL_PATH = "/etc/bind/named.conf.local"
BIND_ZONE_DIR = "/etc/bind"  # zone file paths in named.conf.local are relative to this if not absolute

SSH_CONNECT_TIMEOUT = 10  # seconds
BACKUP_FILENAME = "record-config.txt"

# Matches:  zone "example.com" { ... file "db.example.com"; ... };
ZONE_BLOCK_PATTERN = re.compile(
    r'zone\s+"([^"]+)"\s*\{([^}]*)\}\s*;',
    re.DOTALL,
)
ZONE_FILE_STATEMENT_PATTERN = re.compile(r'file\s+"([^"]+)"')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class DnsDevice:
    """A single DNS server row parsed out of network_devices.csv."""

    def __init__(self, device_id, name, address, username, password):
        self.device_id = device_id
        self.name = name
        self.address = address
        self.username = username
        self.password = password

    def __repr__(self):
        return f"DnsDevice(id={self.device_id}, name={self.name!r}, address={self.address!r})"


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def load_dns_devices(csv_path):
    """
    Read network_devices.csv and return a list of DnsDevice objects, one
    for each name in DEVICE_NAME_TO_SUBDIR (DNS1, DNS2), in that order.

    Handles either comma- or tab-delimited exports automatically.

    Raises:
        FileNotFoundError: csv_path does not exist.
        ValueError: the CSV is missing a required column or a required
            DNS device row.
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
        required_columns = {"Device ID", "Device Name", "Device Address", "Username", "Password"}
        missing_columns = required_columns - set(reader.fieldnames or [])
        if missing_columns:
            raise ValueError(f"CSV is missing required column(s): {', '.join(sorted(missing_columns))}")

        found = {}
        for row in reader:
            name = row["Device Name"].strip()
            if name in DEVICE_NAME_TO_SUBDIR:
                found[name] = DnsDevice(
                    device_id=row["Device ID"].strip(),
                    name=name,
                    address=row["Device Address"].strip(),
                    username=row["Username"].strip(),
                    password=row["Password"].strip(),
                )

    missing_devices = set(DEVICE_NAME_TO_SUBDIR) - set(found)
    if missing_devices:
        raise ValueError(f"CSV is missing expected DNS device(s): {', '.join(sorted(missing_devices))}")

    return [found[name] for name in DEVICE_NAME_TO_SUBDIR]


# ---------------------------------------------------------------------------
# SSH / SFTP helpers
# ---------------------------------------------------------------------------

def connect_ssh(device):
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


def read_remote_file(ssh_client, remote_path):
    """
    Return the contents of remote_path as a string via SFTP, or None if
    the file does not exist or cannot be read.
    """
    sftp = ssh_client.open_sftp()
    try:
        with sftp.open(remote_path, "r") as remote_file:
            return remote_file.read().decode("utf-8", errors="replace")
    except (FileNotFoundError, IOError):
        return None
    finally:
        sftp.close()


# ---------------------------------------------------------------------------
# named.conf.local parsing
# ---------------------------------------------------------------------------

def extract_zone_file_paths(named_conf_local_text):
    """
    Parse named.conf.local content and return a list of (zone_name, file_path)
    tuples for every zone block that declares a "file" statement.
    """
    entries = []
    for zone_name, block_body in ZONE_BLOCK_PATTERN.findall(named_conf_local_text):
        file_match = ZONE_FILE_STATEMENT_PATTERN.search(block_body)
        if file_match:
            entries.append((zone_name, file_match.group(1)))
    return entries


def resolve_zone_path(file_path):
    """
    BIND zone file paths may be absolute or relative to the directory
    named.conf lives in (conventionally /etc/bind). Normalize relative
    paths against BIND_ZONE_DIR.
    """
    if file_path.startswith("/"):
        return file_path
    return f"{BIND_ZONE_DIR.rstrip('/')}/{file_path}"


# ---------------------------------------------------------------------------
# Backup content assembly
# ---------------------------------------------------------------------------

def build_backup_content(device, named_conf_local_text, zone_files):
    """
    Combine named.conf.local and every zone file's contents into a single,
    clearly labeled text block suitable for record-config.txt.

    zone_files: list of (zone_name, resolved_path, contents_or_None) tuples.
    """
    lines = []
    lines.append("=" * 70)
    lines.append(f"DNS CONFIGURATION BACKUP - {device.name} ({device.address})")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"--- {NAMED_CONF_LOCAL_PATH} ---")
    lines.append("")
    lines.append(named_conf_local_text.rstrip("\n") if named_conf_local_text else "(file not found or empty)")
    lines.append("")

    for zone_name, resolved_path, contents in zone_files:
        lines.append("-" * 70)
        lines.append(f"--- Zone: {zone_name}  (file: {resolved_path}) ---")
        lines.append("")
        lines.append(contents.rstrip("\n") if contents is not None else "(file not found or unreadable)")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Per-device backup
# ---------------------------------------------------------------------------

def backup_device(device, output_root):
    """
    SSH into `device`, pull named.conf.local plus every zone file it
    references, and write the combined result to:

        <output_root>/<subdir>/record-config.txt

    where <subdir> is DEVICE_NAME_TO_SUBDIR[device.name].

    Returns the Path of the file written.
    """
    log.info("Connecting to %s (%s)...", device.name, device.address)
    client = connect_ssh(device)
    try:
        named_conf_local_text = read_remote_file(client, NAMED_CONF_LOCAL_PATH)
        if named_conf_local_text is None:
            log.warning("%s: %s not found on remote host", device.name, NAMED_CONF_LOCAL_PATH)
            zone_entries = []
        else:
            zone_entries = extract_zone_file_paths(named_conf_local_text)
            log.info("%s: found %d zone declaration(s) in named.conf.local", device.name, len(zone_entries))

        zone_files = []
        for zone_name, file_path in zone_entries:
            resolved_path = resolve_zone_path(file_path)
            contents = read_remote_file(client, resolved_path)
            if contents is None:
                log.warning("%s: zone file %s not found on remote host", device.name, resolved_path)
            zone_files.append((zone_name, resolved_path, contents))
    finally:
        client.close()

    backup_content = build_backup_content(device, named_conf_local_text, zone_files)

    subdir = DEVICE_NAME_TO_SUBDIR[device.name]
    dest_dir = output_root / subdir
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / BACKUP_FILENAME
    dest_file.write_text(backup_content, encoding="utf-8")

    log.info("%s: backup written to %s", device.name, dest_file)
    return dest_file


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """
    Run the full backup with no external input required: reads
    CSV_PATH, connects to DNS1 and DNS2, and writes into OUTPUT_DIR.
    """
    try:
        devices = load_dns_devices(CSV_PATH)
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    failures = []
    for device in devices:
        try:
            backup_device(device, OUTPUT_DIR)
        except ConnectionError as exc:
            log.error(str(exc))
            failures.append(device.name)

    if failures:
        log.error("Backup failed for: %s", ", ".join(failures))
        sys.exit(1)

    log.info("DNS backup complete. Output directory: %s", OUTPUT_DIR.resolve())


if __name__ == "__main__":
    main()