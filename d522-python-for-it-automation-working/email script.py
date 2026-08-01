import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_incident_alert(devices, recipients):
    """
    Sends an automated incident alert email listing ALL compromised devices.
    Each device must contain: hostname, ip, service.
    """

    subject = "URGENT: Device Compromise Detected—Immediate Attention Required"

    # Build device list section
    device_section = ""
    for d in devices:
        device_section += (
            f"Device Name: {d['hostname']}\n"
            f"IP Address: {d['ip']}\n"
            f"Service: {d['service']}\n"
            "-----------------------------\n"
        )

    # Email body using template wording
    body = f"""
Dear Stakeholders,

This is an automated alert to inform you that the following device(s) have been identified as compromised during the recent network scan:

{device_section}
Last Checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Immediate investigation and remediation are recommended to prevent further impact.

If you have any questions or require additional information, please contact the IT support team.

Best regards,
Network Monitoring System
"""

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = "network-monitor@yourdomain.com"
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "plain"))

    smtp_server = "smtp.d522.wgu.internal"
    smtp_port = 8025
    smtp_user = "Ubuntu"
    smtp_pass = "ubuntu"

    print(body)

    credentials_configured = (
        smtp_user != "your_email@gmail.com"
        and smtp_pass != "your_app_password"
    )

    if not credentials_configured:
        print("SMTP credentials not configured. Alert email not sent.")
        return

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(msg["From"], recipients, msg.as_string())
        print("Incident alert email sent successfully.")
    except Exception as exc:
        print(f"Unable to send alert email: {exc}")


# Example usage
if __name__ == "__main__":
    compromised_devices = [
        {"hostname": "SVR1", "ip": "10.0.5.12", "service": "DNS"},
        {"hostname": "PC1", "ip": "10.0.8.44", "service": "SSH"},
        {"hostname": "PC2", "ip": "10.0.9.77", "service": "MySQL"}
    ]

    stakeholders = ["stakeholder1@example.com", "stakeholder2@example.com"]

    send_incident_alert(compromised_devices, stakeholders)
