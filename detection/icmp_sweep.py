from collections import defaultdict
import time

## ICMP sweep detection logic

icmp_tracker = defaultdict(lambda: {
    "first_seen": 0,
    "dest_ips": set()
})

def detect_icmp_sweep(parsed_packet):
    THRESHOLD_UNIQUE_DEST_IPS = 5
    TIME_WINDOW = 120  # seconds

    current_time = time.time()

    src_ip = parsed_packet.get("src_ip")
    dst_ip = parsed_packet.get("dst_ip")
    icmp_type = parsed_packet.get("type")  # Echo Request = 8

    if not src_ip or not dst_ip or icmp_type != 8:
        return None

    entry = icmp_tracker[src_ip]

    if entry["first_seen"] == 0:
        entry["first_seen"] = current_time

    if current_time - entry["first_seen"] <= TIME_WINDOW:
        entry["dest_ips"].add(dst_ip)
    else:
        entry["first_seen"] = current_time
        entry["dest_ips"].clear()
        entry["dest_ips"].add(dst_ip)

    if len(entry["dest_ips"]) >= THRESHOLD_UNIQUE_DEST_IPS:
        alert = {
            "alert_type": "ICMP_SWEEP",
            "severity": "MEDIUM",
            "description": "ICMP echo requests sent to multiple hosts",
            "src_ip": src_ip,
            "dst_ip": "MULTIPLE",
            "additional_info": {
                "unique_destinations": len(entry["dest_ips"]),
                "dest_ips": list(entry["dest_ips"])
            }
        }

        entry["first_seen"] = 0
        entry["dest_ips"].clear()

        return alert

    return None
