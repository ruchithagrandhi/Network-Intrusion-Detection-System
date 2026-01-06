
from collections import defaultdict
from utils.logger import log_alert
import time
MONITORED_IP = {"ip": None}
  # set dynamically later
TRUSTED_IPS = {
    "192.168.0.1",    # Router
    "192.168.0.108",  # Your system
}
packet_count = defaultdict(int)
port_access = defaultdict(set)
TIME_WINDOW = 10
THRESHOLD = 20
PORT_SCAN_THRESHOLD = 5
start_time = time.time()
def analyze_packet(src_ip, dst_ip, dst_port=None):
    global start_time

    # 🚫 WHITELIST CHECK (FIRST LINE)
    if src_ip in TRUSTED_IPS:
        return
    # IP-based monitoring
    if MONITORED_IP["ip"]:
        if src_ip != MONITORED_IP["ip"] and dst_ip != MONITORED_IP["ip"]:
            return


    packet_count[src_ip] += 1

    if dst_port:
        port_access[src_ip].add(dst_port)

    current_time = time.time()

    if current_time - start_time > TIME_WINDOW:
        for ip in list(packet_count.keys()):

            # Extra safety
            if ip in TRUSTED_IPS:
                continue

            # HIGH severity: Flood / DDoS
            if packet_count[ip] > THRESHOLD:
                log_alert(
                    ip,
                    packet_count[ip],
                    "Possible Flood / DDoS Attack",
                    severity="HIGH"
                )

            # MEDIUM severity: Port Scanning
            if len(port_access[ip]) > PORT_SCAN_THRESHOLD:
                log_alert(
                    ip,
                    len(port_access[ip]),
                    "Possible Port Scanning Attack",
                    severity="MEDIUM"
                )

        packet_count.clear()
        port_access.clear()
        start_time = current_time
