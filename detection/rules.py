from detection.portscan import detect_port_scan
from detection.icmp_sweep import detect_icmp_sweep

def apply_rules(parsed_packet):
    alerts = []

    protocol = parsed_packet.get("protocol")
    if not protocol:
        return alerts

    if protocol == "TCP":
        alert = detect_port_scan(parsed_packet)
        if alert:
            alerts.append(alert)

    elif protocol == "ICMP":
        alert = detect_icmp_sweep(parsed_packet)
        if alert:
            alerts.append(alert)

    return alerts
