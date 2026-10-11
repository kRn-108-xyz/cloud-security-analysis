
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# Project data folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FOLDER = PROJECT_ROOT / "data"
DATA_FOLDER.mkdir(exist_ok=True)

OUTPUT_FILE = DATA_FOLDER / "security_logs.csv"

event_types = [
    "Successful Login",
    "Failed Login",
    "Port Scan",
    "Malware Alert",
    "Suspicious File",
]

# Sample event counts for our college project
event_counts = {
    "Successful Login": 50,
    "Failed Login": 25,
    "Port Scan": 10,
    "Malware Alert": 5,
    "Suspicious File": 10,
}

sample_ips = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.20",
    "10.0.0.5",
    "10.0.0.12",
]

random.seed(42)
events = []

start_time = datetime.now() - timedelta(hours=24)

for event_type, count in event_counts.items():
    for _ in range(count):
        event_time = start_time + timedelta(
            seconds=random.randint(0, 86400)
        )

        events.append({
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": random.choice(sample_ips),
            "event_type": event_type,
        })

# Mix the event order
random.shuffle(events)

# Save the data to CSV
with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=["timestamp", "source_ip", "event_type"]
    )
    writer.writeheader()
    writer.writerows(events)

print("Cybersecurity sample logs generated successfully!")
print(f"Total events: {len(events)}")
print(f"Saved to: {OUTPUT_FILE}")
print("\nEvent counts:")

for event_type, count in event_counts.items():
    print(f"{event_type}: {count}")
