#!/usr/bin/env python3
"""
Send a resolution notification email to stakeholders after the DNS service
issue has been remediated. Device list is pulled from network_devices.csv.
"""

import csv
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path


# ── Configuration ────────────────────────────────────────────────────────────

CSV_PATH = Path("/home/student/d522/d522-python-for-it-automation/network_devices.csv")

# SMTP server settings — update to match your environment
SMTP_HOST = "smtp.d522.wgu.internal"
SMTP_PORT = 8025

# Email addresses
SENDER       = "nms@d522.wgu.internal"
STAKEHOLDERS = [
    "stakeholder1@d522.wgu.internal",
    "stakeholder2@d522.wgu.internal",
]

# Devices to exclude from the affected list — infrastructure that wasn't
# impacted (switches, DHCP-only clients, the DNS servers themselves)
SKIP_OS           = {"openvswitch"}
SKIP_NAMES_PREFIX = ("DNS", "SMTP")
SKIP_DHCP         = True


# ── Device loader ─────────────────────────────────────────────────────────────

def load_affected_devices(csv_path: Path) -> list[dict]:
    """Return a list of affected devices with hostname and IP from the CSV."""
    devices = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name    = (row.get("Device Name")   or "").strip()
                address = (row.get("Device Address") or "").strip()
                os_type = (row.get("OS")             or "").strip().lower()

                if os_type in SKIP_OS:
                    continue
                if any(name.startswith(p) for p in SKIP_NAMES_PREFIX):
                    continue
                if SKIP_DHCP and address.upper() == "DHCP":
                    continue
                if not address:
                    continue

                devices.append({"hostname": name, "ip": address})

    except FileNotFoundError:
        print(f"FAILED: CSV not found at {csv_path}")
        sys.exit(1)
    except Exception as e:
        print(f"FAILED: Could not read CSV: {e}")
        sys.exit(1)

    return devices


# ── Email builder ─────────────────────────────────────────────────────────────

def build_device_list(devices: list[dict]) -> str:
    """Format the device list for the email body."""
    lines = []
    for d in devices:
        lines.append(f"  - {d['hostname']} ({d['ip']})")
    return "\n".join(lines)


def build_email(device_list_str: str) -> MIMEMultipart:
    """Construct the MIME email message."""
    subject = "RESOLVED: DNS Service Issue and Device Compromise—All Issues Remediated"

    body = f"""Dear Stakeholders,

This is an automated notification to inform you that the DNS service issue and all related device compromises have been successfully resolved. The following devices were affected and have now been remediated:

{device_list_str}

No further action is required at this time. If you have any questions or concerns, please contact the IT support team.

Thank you for your attention.

Best regards,
Network Monitoring System"""

    msg = MIMEMultipart()
    msg["From"]    = SENDER
    msg["To"]      = ", ".join(STAKEHOLDERS)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    return msg


# ── Sender ────────────────────────────────────────────────────────────────────

def send_email(msg: MIMEMultipart) -> bool:
    """Send the email via SMTP. Returns True on success, False on failure."""
    try:
        print(f"Connecting to SMTP server {SMTP_HOST}:{SMTP_PORT}…")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.sendmail(SENDER, STAKEHOLDERS, msg.as_string())
        print("OK: Email sent successfully.")
        return True
    except ConnectionRefusedError:
        print(f"FAILED: SMTP server at {SMTP_HOST}:{SMTP_PORT} refused the connection.")
    except TimeoutError:
        print(f"FAILED: Connection to {SMTP_HOST}:{SMTP_PORT} timed out.")
    except smtplib.SMTPException as e:
        print(f"FAILED: SMTP error: {e}")
    except OSError as e:
        print(f"FAILED: Network error: {e}")
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"Reading affected devices from: {CSV_PATH}\n")

    devices = load_affected_devices(CSV_PATH)
    if not devices:
        print("FAILED: No affected devices found in CSV.")
        return 1

    print("Affected devices:")
    for d in devices:
        print(f"  {d['hostname']} — {d['ip']}")
    print()

    device_list_str = build_device_list(devices)
    msg = build_email(device_list_str)

    print(f"Sending notification to: {', '.join(STAKEHOLDERS)}")
    print(f"Subject: {msg['Subject']}\n")

    success = send_email(msg)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())