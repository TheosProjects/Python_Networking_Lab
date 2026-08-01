import argparse
import csv
import json
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode


DEFAULT_CSV_PATH = "/home/student/d522/d522-python-for-it-automation/network_devices.csv"
DEFAULT_ENDPOINT = "https://api.d522.wgu.internal:5000/tickets"  # Replace with the actual ticket service endpoint
API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"


def read_network_devices(file_path: str = DEFAULT_CSV_PATH) -> list[dict[str, str]]:
	devices: list[dict[str, str]] = []
	try:
		with open(file_path, mode="r", newline="", encoding="utf-8") as csv_file:
			reader = csv.DictReader(csv_file)
			for row in reader:
				devices.append(row)
	except FileNotFoundError:
		print(f"Error: '{file_path}' not found.")
	except Exception as error:
		print(f"Error reading '{file_path}': {error}")
	return devices


def build_ticket_payload(issue_type: str, device: dict[str, str]) -> dict[str, Any]:
	device_name = device.get("Device Name", "Unknown device")
	device_address = device.get("Device Address", "Unknown address")

	return {
		"issue_type": issue_type,
		"targeted_devices": [device],
		"summary": f"{issue_type}: {device_name}",
		"description": (
			f"Automated ticket created for device {device_name} "
			f"({device_address})."
		),
	}


def create_ticket(endpoint_url: str, payload: dict[str, Any], api_token: str | None = None) -> dict[str, Any]:
	headers = {
		"Content-Type": "application/json",
		"Accept": "application/json",
	}
	if api_token:
		headers["Authorization"] = f"Bearer {api_token}"

	request_url = f"{endpoint_url}?{urlencode({'payload': json.dumps(payload)})}"
	print(f"Sending GET request to: {request_url}")
	req = request.Request(request_url, headers=headers, method="GET")

	with request.urlopen(req) as response:
		content_type = response.headers.get_content_type()
		response_body = response.read().decode("utf-8")
		if content_type == "application/json" and response_body:
			return json.loads(response_body)
		return {"status": response.status, "body": response_body}


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Create one ticket per network device from a CSV file."
	)
	parser.add_argument("--csv-path", default=DEFAULT_CSV_PATH, help="Path to the network devices CSV file.")
	parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT, help="Ticket service GET endpoint.")

	parser.add_argument(
		"--api-token",
		default=API_TOKEN,
		help="Optional bearer token for authenticated ticket service requests.",
	)
	parser.add_argument(
		"--dry-run",
		action="store_true",
		help="Print each payload instead of sending it to the web service.",
	)
	parser.add_argument(
		"--issue-type",
		default="Outage",
		help="Issue type to record for each ticket, for example 'Outage' or 'Compromised device'.",
	)
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	network_devices = read_network_devices(args.csv_path)

	if not network_devices:
		print("No network devices were found.")
		return

	for index, device in enumerate(network_devices, start=1):
		payload = build_ticket_payload(args.issue_type, device)
		device_name = device.get("Device Name", f"Device {index}")

		if args.dry_run:
			print(json.dumps(payload, indent=2))
			continue

		try:
			response = create_ticket(args.endpoint_url, payload, args.api_token)
			print(f"Created ticket for {device_name}: {response}")
		except HTTPError as error:
			print(f"Failed to create ticket for {device_name}: HTTP {error.code} - {error.reason}")
		except URLError as error:
			print(f"Failed to create ticket for {device_name}: {error.reason}")
		except Exception as error:
			print(f"Failed to create ticket for {device_name}: {error}")


if __name__ == "__main__":
	main()