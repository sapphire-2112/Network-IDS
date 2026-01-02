import time
from collections import defaultdict, deque

# Time windows in seconds (industry-style multi-window)
WINDOWS = {
    "short": 10,     # fast scans, bursts
    "medium": 60,    # normal scans
    "long": 300      # stealth / low-and-slow
}

# Feature storage:
# src_ip → window → deque of (timestamp, feature_dict)
feature_store = defaultdict(lambda: {
    window: deque() for window in WINDOWS
})


def store_features(src_ip, features):
    """
    Store extracted features for a source IP across multiple time windows.
    """
    now = time.time()

    for window, duration in WINDOWS.items():
        store = feature_store[src_ip][window]
        store.append((now, features))

        # Remove expired entries
        while store and (now - store[0][0]) > duration:
            store.popleft()


def get_aggregated_features(src_ip):
    """
    Aggregate features per time window for anomaly detection.
    """
    aggregated = {}

    for window in WINDOWS:
        entries = feature_store[src_ip][window]
        if not entries:
            continue

        total_packets = sum(f["packet_rate"] for _, f in entries)
        total_tcp_syn = sum(f["tcp_syn_rate"] for _, f in entries)
        total_icmp = sum(f["icmp_rate"] for _, f in entries)

        aggregated[window] = {
            "packet_rate_avg": total_packets / len(entries),
            "tcp_syn_rate_avg": total_tcp_syn / len(entries),
            "icmp_rate_avg": total_icmp / len(entries),
            "samples": len(entries)
        }

    return aggregated
