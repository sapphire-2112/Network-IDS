from collections import defaultdict
import time

## Here I will be implementing ICMP sweep detection logic
# The whole logic is to store a dictionary set of source ip to destination ip..
# like port scan detection..
# If a source ip sends ICMP echo requests to more than a threshold number of unique destination ips
# within a defined time window, it will raise an alert for ICMP sweep detection.

icmp_tracker = defaultdict(lambda: {
    "first_seen": 0,
    "dest_ips": set()
})

def detect_icmp_sweep(parsed_packet):
    """
    Detect ICMP sweep attacks based on parsed packet data.
    """
    THRESHOLD_UNIQUE_DEST_IPS = 20
    TIME_WINDOW = 120  # seconds    

    current_time = time.time()

    src_ip = parsed_packet.get("src_ip")
    dst_ip = parsed_packet.get("dst_ip")
    icmp_type = parsed_packet.get("type")   # from parse_icmp_packet()

    ## ICMP Just sees the request and it's type 8 (Echo Request)
    if not src_ip or not dst_ip or icmp_type != 8:
        return

    entry = icmp_tracker[src_ip]

    # First packet seen from this source
    if entry["first_seen"] == 0:
        entry["first_seen"] = current_time

    # If still inside time window
    if current_time - entry["first_seen"] <= TIME_WINDOW:
        entry["dest_ips"].add(dst_ip)

    # Time window expired → reset tracking
    else:
        entry["first_seen"] = current_time
        entry["dest_ips"].clear()
        entry["dest_ips"].add(dst_ip)

    # Detection condition
    if len(entry["dest_ips"]) >= THRESHOLD_UNIQUE_DEST_IPS:
        print(f"[ALERT] ICMP sweep detected!! from {src_ip}")
        print(f"        Destination IPs targeted: {sorted(entry['dest_ips'])}")

        # Reset after alert
        entry["first_seen"] = 0
        entry["dest_ips"].clear()
