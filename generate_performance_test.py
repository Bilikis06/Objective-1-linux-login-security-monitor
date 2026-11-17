import json
from pathlib import Path
from datetime import datetime, timedelta

output = Path("output/performance_test_events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

start = datetime(2026, 11, 17, 10, 0, 0)

with output.open("w") as file:
    for i in range(1000):
        host_number = (i % 10) + 1
        ip_number = (i % 20) + 1
        event_time = start + timedelta(minutes=(i // 20) * 5)

        event = {
            "host": f"server{host_number:02d}",
            "source_ip": f"192.168.1.{ip_number}",
            "window_start": event_time.isoformat(),
            "window_end": (
                event_time + timedelta(minutes=5)
            ).isoformat(),
            "failed_attempt_count": 4,
            "alert": True,
            "usernames": ["admin"],
            "asset": {
                "asset_id": f"AST{host_number:03d}",
                "asset_type": "Test Server",
                "criticality": "High"
            }
        }

        file.write(json.dumps(event) + "\n")

print("Performance test dataset created.")
print("Total records:", 1000)
print("File:", output)
