from collections import defaultdict

ports_scanned = defaultdict(set)

def detect_port_scan(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src = packet["IP"].src
        dport = packet["TCP"].dport

        ports_scanned[src].add(dport)

        if len(ports_scanned[src]) > 5:
            print(f"\n🚨 [ALERT] Port Scan Detected from {src} — scanned {len(ports_scanned[src])} ports\n")
