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

def detect_new_ip(events):
    alerts = []
    user_ips = defaultdict(set)

    for ts, user, ip, status in events:
        if status == "SUCCESS":
            if ip not in user_ips[user] and len(user_ips[user]) > 0:
                alerts.append(
                    f"[NEW IP LOGIN] user={user} new_ip={ip}"
                )
            user_ips[user].add(ip)
    return alerts

if __name__ == "__main__":
    events = load_logs(LOG_FILE)
    aldef detect_impossible_travel(events):
    alerts = []
    user_logins = defaultdict(list)

    for ts, user, ip, status in events:
        if status == "SUCCESS":
            user_logins[user].append((ts, ip))

    for user, logins in user_logins.items():
        logins.sort()
        for i in range(len(logins) - 1):
            t1, ip1 = logins[i]
            t2, ip2 = logins[i + 1]
            if ip1 != ip2:
                diff_minutes = (t2 - t1).total_seconds() / 60
                if diff_minutes < 10:
                    alerts.append(
                        f"[IMPOSSIBLE TRAVEL] user={user} ip1={ip1} ip2={ip2} delta={diff_minutes:.2f}m"
                    )
    return alerts

if __name__ == "__main__":
    events = load_logs(LOG_FILE)
    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_after_hours(events))
    alerts.extend(detect_new_ip(events))
    alerts.extend(detect_impossible_travel(events))

    if alerts:
        print("=== SECURITY ALERTS ===")
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious activity detected.")
erts = detect_bruteforce(events)
    alerts.extend(detect_after_hours(events))
    alerts.extend(detect_new_ip(events))
    print(alerts)





