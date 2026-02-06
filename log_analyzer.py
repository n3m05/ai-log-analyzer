# log_analyzer.py
import datetime
from collections import defaultdict

LOG_FILE = "auth.log"

def parse_log_line(line):
    try:
        parts = line.strip().split()
        timestamp = datetime.datetime.fromisoformat(parts[0])
        user = parts[1].split("=")[1]
        ip = parts[2].split("=")[1]
        status = parts[3].split("=")[1]
        return timestamp, user, ip, status
    except Exception:
        return None

def load_logs(file_path):
    events = []
    with open(file_path, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events

if __name__ == "__main__":
    events = load_logs(LOG_FILE)
    print(events[:5])  # Show first 5 events for testing
