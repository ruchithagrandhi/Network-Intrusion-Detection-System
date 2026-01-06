import sys
import os
import subprocess
from flask import Flask, render_template, request, redirect
from collections import Counter

# -------------------------------
# PROJECT ROOT CONFIG
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# -------------------------------
# IMPORT SHARED DATA
# -------------------------------
from engine.rules import MONITORED_IP

# -------------------------------
# APP CONFIG
# -------------------------------
app = Flask(__name__)
LOG_FILE = os.path.join("logs", "alerts.log")

# -------------------------------
# HELPER FUNCTION
# -------------------------------
def get_connected_devices():
    """
    Discover devices connected to the same local network (Wi-Fi)
    Uses ARP table
    """
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 1 and "." in parts[0]:
                devices.append(parts[0])
        return list(set(devices))
    except Exception:
        return []

# -------------------------------
# ROUTES
# -------------------------------
@app.route("/")
def index():
    logs = []
    suspicious_logs = []
    severities = Counter()
    attacks = Counter()
    ip_stats = Counter()

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                logs.append(line)

                # Expected log format:
                # timestamp | ip | attack | Severity: HIGH | Count: 123
                parts = line.split("|")

                if len(parts) >= 3:
                    ip = parts[1].strip()
                    attack = parts[2].strip()
                    ip_stats[ip] += 1
                    attacks[attack] += 1

                if "Severity:" in line:
                    sev = line.split("Severity:")[1].split("|")[0].strip()
                    severities[sev] += 1

                if "Possible" in line:
                    suspicious_logs.append(line)

    # Limit suspicious logs
    suspicious_logs = suspicious_logs[-10:]

    # Get connected devices
    connected_devices = get_connected_devices()

    return render_template(
        "index.html",
        logs=logs[-20:],
        suspicious_logs=suspicious_logs,
        total=len(logs),
        severities=severities,
        attacks=attacks,
        ip_stats=ip_stats,
        monitored_ip=MONITORED_IP["ip"],
        connected_devices=connected_devices
    )

# -------------------------------
# SET MONITORED IP
# -------------------------------
@app.route("/set_ip", methods=["POST"])
def set_ip():
    ip = request.form.get("ip")

    if ip and ip.strip():
        MONITORED_IP["ip"] = ip.strip()
    else:
        MONITORED_IP["ip"] = None

    return redirect("/")

# -------------------------------
# IP HISTORY PAGE
# -------------------------------
@app.route("/history", methods=["GET", "POST"])
def history():
    results = []
    ip = None

    if request.method == "POST":
        ip = request.form.get("ip")
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                for line in f:
                    if ip in line:
                        results.append(line.strip())

    return render_template("history.html", results=results, ip=ip)

# -------------------------------
# RUN APP
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
