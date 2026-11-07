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