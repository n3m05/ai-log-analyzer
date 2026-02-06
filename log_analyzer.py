# log_analyzer.py
import datetime
from collections import defaultdict

LOG_FILE = "auth.log"

FAIL_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
AFTER_HOURS_START = 22
AFTER_HOURS_END = 5

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

def detect_bruteforce(events):
    alerts = []
    user_failures = defaultdict(list)

    for ts, user, ip, status in events:
        if status == "FAIL":
            user_failures[(user, ip)].append(ts)

    for key, timestamps in user_failures.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [
                t for t in timestamps
                if 0 <= (t - timestamps[i]).total_seconds() <= TIME_WINDOW_MINUTES * 60
            ]
            if len(window) >= FAIL_THRESHOLD:
                alerts.append(
                    f"[BRUTEFORCE] user={key[0]} ip={key[1]} failures={len(window)}"
                )
                break
    return alerts

def detect_after_hours(events):
    alerts = []
    for ts, user, ip, status in events:
        if status == "SUCCESS":
            hour = ts.hour
            if hour >= AFTER_HOURS_START or hour <= AFTER_HOURS_END:
                alerts.append(
                    f"[AFTER HOURS LOGIN] user={user} ip={ip} time={ts}"
                )
    return alerts

if __name__ == "__main__":
    events = load_logs(LOG_FILE)
    alerts = detect_bruteforce(events)
    alerts.extend(detect_after_hours(events))
    print(alerts)




