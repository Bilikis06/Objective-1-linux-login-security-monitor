import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.request import Request, urlopen


INPUT_FILE = Path("output/siem_ready_events.jsonl")
HOST = "127.0.0.1"
PORT = 8765


received_events = []


class MockSIEMHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404, "Endpoint not found")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            events = json.loads(body.decode("utf-8"))

            if not isinstance(events, list):
                raise ValueError("Expected a list of events")

            received_events.extend(events)

            response = {
                "status": "accepted",
                "received": len(events)
            }

            response_body = json.dumps(response).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON payload")

    def log_message(self, format, *args):
        pass


def load_events():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"SIEM output file not found: {INPUT_FILE}"
        )

    events = []

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {error}"
                )

    if not events:
        raise ValueError("No SIEM-ready events were found.")

    return events


def main():
    events = load_events()

    server = HTTPServer((HOST, PORT), MockSIEMHandler)

    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )
    server_thread.start()

    try:
        payload = json.dumps(events).encode("utf-8")

        request = Request(
            f"http://{HOST}:{PORT}/webhook",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))

        print("MOCK SIEM WEBHOOK TEST")
        print("----------------------")
        print(f"Events prepared: {len(events)}")
        print(f"HTTP response: {response.status}")
        print(f"Webhook status: {result['status']}")
        print(f"Events received: {result['received']}")

        if (
            response.status == 200
            and result["status"] == "accepted"
            and result["received"] == len(events)
            and len(received_events) == len(events)
        ):
            print("RESULT: PASSED")
            print("The mock SIEM successfully received the events.")
        else:
            print("RESULT: FAILED")

    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
