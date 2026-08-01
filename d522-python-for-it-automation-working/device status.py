import platform
import socket
import subprocess
from typing import Iterable


DEVICES = [
	"PC1",
	"PC2",
	"SVR1",
]

DNS_HOSTS_TO_VERIFY = [
	"10.10.10.10",
		"10.10.10.20",
		"ns1.d522.wgu.internal",
]


def ping(host: str, timeout_ms: int = 1000) -> bool:
	system = platform.system().lower()
	if system == "windows":
		cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
	else:
		timeout_s = max(1, timeout_ms // 1000)
		cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]

	result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	return result.returncode == 0


def check_dns_resolution(hostname: str) -> tuple[bool, str]:
	try:
		resolved_ip = socket.gethostbyname(hostname)
		return True, resolved_ip
	except socket.gaierror as ex:
		return False, str(ex)


def report_device_status(devices: Iterable[str]) -> None:
	print("=== Device Reachability ===")
	for device in devices:
		is_up = ping(device)
		status = "UP" if is_up else "DOWN"
		print(f"{device}: {status}")


def report_dns_status(hosts: Iterable[str]) -> None:
	print("\n=== DNS Verification ===")
	for host in hosts:
		ok, details = check_dns_resolution(host)
		status = "OK" if ok else "FAIL"
		print(f"{host}: {status} ({details})")


if __name__ == "__main__":
	report_device_status(DEVICES)
	report_dns_status(DNS_HOSTS_TO_VERIFY)
