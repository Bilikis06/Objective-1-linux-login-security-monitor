import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
import time

# File locations
INPUT_FILE = Path("output/aggregated_events.jsonl")
OUTPUT_FILE = Path("output/siem_ready_events.jsonl")
REPORT_FILE = Path("output/correlation_report.txt")

# Correlation settings
CORRELATION_WINDOW_MINUTES = 15

# Required event fields
REQUIRED_FIELDS = [
    "host",
    "source_ip",
    "window_start",
    "window_end",
    "failed_attempt_count",
    "alert"
]


def load_events():
    """Load valid aggregated events and count invalid records."""

    events = []
    invalid_records = 0

    try:
        with INPUT_FILE.open("r") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)

                    if not isinstance(event, dict):
                        invalid_records += 1
                        continue

                    if not all(field in event for field in REQUIRED_FIELDS):
                        invalid_records += 1
                        continue

                    datetime.fromisoformat(event["window_start"])
                    datetime.fromisoformat(event["window_end"])

                    if (
                        not isinstance(event["failed_attempt_count"], int)
                        or isinstance(event["failed_attempt_count"], bool)
                        or event["failed_attempt_count"] < 0
                        or not isinstance(event["alert"], bool)
                        or not isinstance(event["host"], str)
                        or not event["host"].strip()
                        or not isinstance(event["source_ip"], str)
                        or not event["source_ip"].strip()
                    ):
                        invalid_records += 1
                        continue

                    events.append(event)

                except (json.JSONDecodeError, ValueError, TypeError):
                    invalid_records += 1

    except FileNotFoundError:
        print(f"Error: Input file not found: {INPUT_FILE}")
        return None, invalid_records

    return events, invalid_records


def correlate_events(events):
    """Group related suspicious events into incidents."""

    alerts = [event for event in events if event.get("alert") is True]

    grouped_events = defaultdict(list)

    for event in alerts:
        key = (event["host"], event["source_ip"])
        grouped_events[key].append(event)

    incidents = []
    correlation_gap = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    for (host, source_ip), records in grouped_events.items():

        records.sort(
            key=lambda event: datetime.fromisoformat(event["window_start"])
        )

        current_incident = None

        for event in records:
            event_start = datetime.fromisoformat(event["window_start"])

            if current_incident is None:
                current_incident = {
                    "host": host,
                    "source_ip": source_ip,
                    "first_seen": event["window_start"],
                    "last_seen": event["window_end"],
                    "total_failed_attempts": event["failed_attempt_count"],
                    "usernames": set(event.get("usernames", [])),
                    "asset": event.get("asset"),
                    "evidence": [event]
                }

            else:
                last_end = datetime.fromisoformat(
                    current_incident["last_seen"]
                )

                if event_start <= last_end + correlation_gap:
                    current_incident["last_seen"] = event["window_end"]
                    current_incident["total_failed_attempts"] += (
                        event["failed_attempt_count"]
                    )
                    current_incident["usernames"].update(
                        event.get("usernames", [])
                    )
                    current_incident["evidence"].append(event)

                else:
                    current_incident["usernames"] = sorted(
                        current_incident["usernames"]
                    )
                    incidents.append(current_incident)

                    current_incident = {
                        "host": host,
                        "source_ip": source_ip,
                        "first_seen": event["window_start"],
                        "last_seen": event["window_end"],
                        "total_failed_attempts": event["failed_attempt_count"],
                        "usernames": set(event.get("usernames", [])),
                        "asset": event.get("asset"),
                        "evidence": [event]
                    }

        if current_incident is not None:
            current_incident["usernames"] = sorted(
                current_incident["usernames"]
            )
            incidents.append(current_incident)

    return alerts, incidents


def main():
    start_time = time.perf_counter()

    events, invalid_records = load_events()

    if events is None:
        return

    alerts, incidents = correlate_events(events)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w") as file:
        for incident in incidents:
            file.write(json.dumps(incident) + "\n")

    processing_time = time.perf_counter() - start_time

    alert_count = len(alerts)
    incident_count = len(incidents)

    if alert_count > 0:
        reduction = (
            (alert_count - incident_count) / alert_count
        ) * 100
    else:
        reduction = 0

    with REPORT_FILE.open("w") as file:
        file.write("OBJECTIVE 2: EVENT CORRELATION REPORT\n")
        file.write("-------------------------------------\n")
        file.write(f"Total valid input records: {len(events)}\n")
        file.write(f"Invalid records skipped: {invalid_records}\n")
        file.write(f"Non-alert records filtered: {len(events) - alert_count}\n")
        file.write(f"Alert records correlated: {alert_count}\n")
        file.write(f"Incidents produced: {incident_count}\n")
        file.write(f"Alert record reduction: {reduction:.2f}%\n")
        file.write(f"Processing time: {processing_time:.6f} seconds\n")

    print("Event correlation completed.")
    print(f"Valid input records: {len(events)}")
    print(f"Invalid records skipped: {invalid_records}")
    print(f"Alert records: {alert_count}")
    print(f"Correlated incidents: {incident_count}")
    print(f"Alert record reduction: {reduction:.2f}%")
    print(f"Processing time: {processing_time:.6f} seconds")


if __name__ == "__main__":
    main()
