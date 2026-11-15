
import json
import re
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# Configuration and file paths
with open("data/config.json") as f:
    config = json.load(f)

with open("data/assets.json") as f:
    assets = json.load(f)

LOG_FILE = "logs/native_test.log"
OUTPUT_FILE = "output/aggregated_events.jsonl"
REPORT_FILE = "output/login_security_report.txt"

window_minutes = config["window_minutes"]
threshold = config["threshold"]
log_year = config["log_year"]

if window_minutes <= 0 or threshold <= 0:
    raise ValueError("Window and threshold must be positive.")

# Recognise the two supported log timestamp formats
iso_pattern = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd(?:\[\d+\])?:? (?P<message>.*)$"
)

ubuntu_pattern = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd(?:\[\d+\])?: "
    r"(?P<message>.*)$"
)

# Extract authentication outcome, username and IP
failed_pattern = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(\S+) from ([0-9a-fA-F:.]+)"
)

success_pattern = re.compile(
    r"Accepted password for (\S+) from ([0-9a-fA-F:.]+)"
)

grouped_events = defaultdict(
    lambda: {
        "failed": 0,
        "successful": 0,
        "usernames": set()
    }
)

total_lines = 0
recognised_events = 0
ignored_lines = 0
malformed_lines = 0

Path("output").mkdir(exist_ok=True)

with open(LOG_FILE, "r") as log:

    for line in log:
        total_lines += 1
        line = line.strip()

        if not line:
            ignored_lines += 1
            continue

        match = iso_pattern.match(line)

        if match:
            timestamp = datetime.strptime(
                match.group("time"), "%Y-%m-%dT%H:%M:%S"
            )
            host = match.group("host")
            message = match.group("message")

        else:
            match = ubuntu_pattern.match(line)

            if not match:
                if "sshd" in line and (
                    "Failed password" in line
                    or "Accepted password" in line
                ):
                    malformed_lines += 1
                else:
                    ignored_lines += 1
                continue

            timestamp = datetime.strptime(
                f"{log_year} {match.group('month')} "
                f"{match.group('day')} {match.group('time')}",
                "%Y %b %d %H:%M:%S"
            )
            host = match.group("host")
            message = match.group("message")

        failed = failed_pattern.search(message)
        successful = success_pattern.search(message)

        if failed:
            outcome = "failed"
            username, ip_address = failed.groups()

        elif successful:
            outcome = "successful"
            username, ip_address = successful.groups()

        else:
            ignored_lines += 1
            continue

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            malformed_lines += 1
            continue

        recognised_events += 1

        window_start = timestamp.replace(
            minute=(timestamp.minute // window_minutes)
            * window_minutes,
            second=0,
            microsecond=0
        )

        key = (host, ip_address, window_start)

        grouped_events[key][outcome] += 1
        grouped_events[key]["usernames"].add(username)

# Generate aggregated output
with open(OUTPUT_FILE, "w") as output:

    for (host, ip, start), event in grouped_events.items():

        asset = assets.get(host, {
            "asset_id": "Unknown",
            "asset_type": "Unknown",
            "criticality": "Unknown"
        })

        failed_count = event["failed"]

        summary = {
            "host": host,
            "source_ip": ip,
            "window_start": start.isoformat(),
            "window_end": (
                start + timedelta(minutes=window_minutes)
            ).isoformat(),
            "failed_attempt_count": failed_count,
            "successful_attempt_count": event["successful"],
            "threshold": threshold,
            "alert": failed_count >= threshold,
            "usernames": sorted(event["usernames"]),
            "asset": asset
        }

        output.write(json.dumps(summary) + "\n")

# Generate security report
with open(REPORT_FILE, "w") as report:

    report.write("LINUX LOGIN SECURITY REPORT\n")
    report.write("===========================\n\n")

    report.write(f"Total log lines: {total_lines}\n")
    report.write(f"Recognised authentication events: {recognised_events}\n")
    report.write(f"Ignored lines: {ignored_lines}\n")
    report.write(f"Malformed records: {malformed_lines}\n")
    report.write(f"Time window: {window_minutes} minutes\n")
    report.write(f"Detection threshold: {threshold}\n\n")

    for (host, ip, start), event in grouped_events.items():

        failed_count = event["failed"]
        status = (
            "SUSPICIOUS ACTIVITY"
            if failed_count >= threshold
            else "BELOW DETECTION THRESHOLD"
        )

        report.write(f"Host: {host}\n")
        report.write(f"Source IP: {ip}\n")
        report.write(f"Failed attempts: {failed_count}\n")
        report.write(f"Successful attempts: {event['successful']}\n")
        report.write(f"Classification: {status}\n")
        report.write(f"Asset: {assets.get(host, 'Unknown')}\n")
        report.write("---------------------------\n")

print("Authentication log analysis completed.")
print("Total lines:", total_lines)
print("Recognised events:", recognised_events)
print("Ignored lines:", ignored_lines)
print("Malformed records:", malformed_lines)
print("Aggregated output:", OUTPUT_FILE)
print("Security report:", REPORT_FILE)
from collections import defaultdict
from datetime import datetime, timedelta
import json

# Configuration
log_file = "logs/auth.log"
output_file = "output/aggregated_events.jsonl"
with open("data/config.json", "r") as config_file:
    config = json.load(config_file)

window_minutes = config["window_minutes"]

# Store grouped failed login attempts
grouped_events = defaultdict(list)

# Read authentication records
with open(log_file, "r") as file:
    for line in file:
        line = line.strip()

        if "Failed password" in line:

            parts = line.split()

            # Extract login information
            timestamp = datetime.strptime(
                parts[0], "%Y-%m-%dT%H:%M:%S"
            )

            server = parts[1]
            username = parts[parts.index("for") + 1]
            ip_address = parts[parts.index("from") + 1]

            # Calculate the five-minute time window
            window_start = timestamp.replace(
                minute=(timestamp.minute // window_minutes)
                * window_minutes,
                second=0,
                microsecond=0
            )

            window_end = window_start + timedelta(
                minutes=window_minutes
            )

            # Group by server, IP address and time window
            group_key = (server, ip_address, window_start)

            grouped_events[group_key].append({
                "timestamp": timestamp.strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
                "username": username
            })

# Generate aggregated summaries
with open(output_file, "w") as report:

    for (server, ip_address, window_start), attempts in grouped_events.items():

        threshold = 3

        failed_count = len(attempts)

        alert = failed_count >= threshold
        
        summary = {
            "host": server,
            "source_ip": ip_address,
            "window_start": window_start.strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
            "window_end": (
                window_start + timedelta(minutes=window_minutes)
            ).strftime("%Y-%m-%dT%H:%M:%S"),
            "failed_attempt_count": failed_count,
            "threshold": threshold,
            "alert": alert,
            "usernames": sorted(set(
                attempt["username"] for attempt in attempts
            ))
        }

        report.write(json.dumps(summary) + "\n")

        print("\nAGGREGATED LOGIN EVENT")
        print("Host:", summary["host"])
        print("Source IP:", summary["source_ip"])
        print("Time window:", summary["window_start"],
              "to", summary["window_end"])
        print("Failed attempts:", summary["failed_attempt_count"])
        print("Usernames:", summary["usernames"])

print("\nAggregation completed successfully.")
print("Results saved to:", output_file)
