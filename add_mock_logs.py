import csv
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
csv_file = BASE_DIR / "filtered_logs.csv"

mock_logs = [
    {
        "timestamp": datetime.now().isoformat(),
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": "9999",
        "event_type": "8",
        "log_type": "Security",
        "computer_name": "sanjeev",
        "record_number": "9999999",
        "event_description": "GUARANTEED ALERT TEST",
        "keywords": "event_9999, microsoft-windows-security-auditing",
        # Added ALL risky behaviors to ensure Heuristic Score > 0.6
        "behavior_features_json": '{"process_creation": true, "privilege_escalation": true, "suspicious_process": true, "service_installation": true, "scheduled_task_creation": true}',
        "raw_message": "('GUARANTEED ALERT TEST')"
    }
]

with open(csv_file, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(mock_logs[0].keys()))
    # Ensure the CSV has headers (Agent 4 + UI tailers rely on them)
    try:
        if f.tell() == 0:
            writer.writeheader()
    except Exception:
        pass
    for log in mock_logs:
        writer.writerow(log)

print("Guaranteed Alert Mock Log Injected Successfully.")
