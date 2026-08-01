import csv


def read_network_devices(file_path="/home/student/d522/d522-python-for-it-automation/network_devices.csv"):
	devices = []
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


if __name__ == "__main__":
	network_devices = read_network_devices()
	print("Network Devices:")
	for index, device in enumerate(network_devices, start=1):
		print(f"{index}. {device}")