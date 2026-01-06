from datetime import datetime

def log_alert(ip, count, attack, severity):
    timestamp = datetime.now()
    log_line = f"{timestamp} | {ip} | {attack} | Severity: {severity} | Count: {count}\n"

    with open("logs/alerts.log", "a") as f:
        f.write(log_line)

    print(f"[ALERT][{severity}] {ip} | {attack} | Count: {count}")
