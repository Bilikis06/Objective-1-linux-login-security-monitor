devasc@labvm:~/cybersecurity_app$ pwd
/home/devasc/cybersecurity_app
devasc@labvm:~/cybersecurity_app$ tail -n 10 login_analyser.py
        report.write(f"Asset: {assets.get(host, 'Unknown')}\n")
        report.write("---------------------------\n")

print("Authentication log analysis completed.")
print("Total lines:", total_lines)
print("Recognised events:", recognised_events)
print("Ignored lines:", ignored_lines)
print("Malformed records:", malformed_lines)
print("Aggregated output:", OUTPUT_FILE)
print("Security report:", REPORT_FILE)
devasc@labvm:~/cybersecurity_app$ ^C
devasc@labvm:~/cybersecurity_app$ cat data/config.json
{
    "window_minutes": 5,
    "threshold": 3,
    "log_year": 2026
}
devasc@labvm:~/cybersecurity_app$ ^C
devasc@labvm:~/cybersecurity_app$ cat data/assets.json

{
    "server01": {
        "asset_id": "AST001",
        "asset_type": "Application Server",
        "criticality": "High"
    },
    "server02": {
        "asset_id": "AST002",
        "asset_type": "Database Server",
        "criticality": "High"
    }
}
devasc@labvm:~/cybersecurity_app$ ls logs/
auth.log  native_test.log  quality_test.log  ubuntu_auth.log
devasc@labvm:~/cybersecurity_app$ cat logs/native_test.log
Nov 15 10:01:15 server01 sshd[1200]: Failed password for admin from 192.168.1.20 port 54321 ssh2
Nov 15 10:02:10 server01 sshd[1201]: Failed password for admin from 192.168.1.20 port 54322 ssh2
Nov 15 10:03:05 server01 sshd[1202]: Failed password for admin from 192.168.1.20 port 54323 ssh2
Nov 15 10:04:20 server01 sshd[1203]: Failed password for root from 192.168.1.20 port 54324 ssh2
Nov 15 10:05:00 server01 sshd[1204]: Accepted password for john from 192.168.1.30 port 54325 ssh2
devasc@labvm:~/cybersecurity_app$ python3 login_analyser.py
Authentication log analysis completed.
Total lines: 5
Recognised events: 5
Ignored lines: 0
Malformed records: 0
Aggregated output: output/aggregated_events.jsonl
Security report: output/login_security_report.txt
devasc@labvm:~/cybersecurity_app$ cat output/aggregated_events.jsonl
{"host": "server01", "source_ip": "192.168.1.20", "window_start": "2026-11-15T10:00:00", "window_end": "2026-11-15T10:05:00", "failed_attempt_count": 4, "successful_attempt_count": 0, "threshold": 3, "alert": true, "usernames": ["admin", "root"], "asset": {"asset_id": "AST001", "asset_type": "Application Server", "criticality": "High"}}
{"host": "server01", "source_ip": "192.168.1.30", "window_start": "2026-11-15T10:05:00", "window_end": "2026-11-15T10:10:00", "failed_attempt_count": 0, "successful_attempt_count": 1, "threshold": 3, "alert": false, "usernames": ["john"], "asset": {"asset_id": "AST001", "asset_type": "Application Server", "criticality": "High"}}
devasc@labvm:~/cybersecurity_app$ cat output/login_security_report.txt
LINUX LOGIN SECURITY REPORT
===========================

Total log lines: 5
Recognised authentication events: 5
Ignored lines: 0
Malformed records: 0
Time window: 5 minutes
Detection threshold: 3

Host: server01
Source IP: 192.168.1.20
Failed attempts: 4
Successful attempts: 0
Classification: SUSPICIOUS ACTIVITY
Asset: {'asset_id': 'AST001', 'asset_type': 'Application Server', 'criticality': 'High'}
---------------------------
Host: server01
Source IP: 192.168.1.30
Failed attempts: 0
Successful attempts: 1
Classification: BELOW DETECTION THRESHOLD
Asset: {'asset_id': 'AST001', 'asset_type': 'Application Server', 'criticality': 'High'}
---------------------------
devasc@labvm:~/cybersecurity_app$ 
