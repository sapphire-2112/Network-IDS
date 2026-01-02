# This module is responsible for detecting TCP port scanning behavior.
# It analyzes parsed packet data (not raw packets).
# It tracks source IPs and the number of unique destination ports
# accessed within a defined time window.
# If a threshold is exceeded, it raises an alert.

import time
from collections import defaultdict

port_scan_dict = defaultdict(lambda: {
    "first_seen": 0,
    "ports": set()
})

def detect_port_scan(parsed_packet):
    "Going to start a rule based port scanner initially.."

    THRESHOLD_PORTS_SCANNED = 10
    TIME_WINDOW = 60  # seconds

    current_time = time.time()

    src_ip = parsed_packet.get("src_ip")
    dst_port = parsed_packet.get("dst_port")
    flags = parsed_packet.get("flags")

    # Only TCP SYN packets are relevant for port scanning
    if not src_ip or not dst_port or flags != "S":
        return None

    entry = port_scan_dict[src_ip]

    if entry["first_seen"] == 0:
        entry["first_seen"] = current_time

    if current_time - entry["first_seen"] <= TIME_WINDOW:
        entry["ports"].add(dst_port)
    else:
        entry["first_seen"] = current_time
        entry["ports"].clear()
        entry["ports"].add(dst_port)

    if len(entry["ports"]) >= THRESHOLD_PORTS_SCANNED:
        alert = {
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "description": "Multiple TCP SYN packets to multiple ports",
            "src_ip": src_ip,
            "dst_ip": parsed_packet.get("dst_ip", "N/A"),
            "additional_info": {
                "ports_scanned": sorted(entry["ports"]),
                "time_window": TIME_WINDOW
            }
        }

        entry["first_seen"] = 0
        entry["ports"].clear()

        return alert

    return None
