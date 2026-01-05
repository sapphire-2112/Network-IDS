from scapy.all import sniff, conf
from parsers.ip import parse_ip_packet
from parsers.tcp import parse_tcp_packet
from parsers.udp import parse_udp_packet
from parsers.icmp import parse_icmp_packet
from parsers.ethernet import parse_ethernet_packet
from detection.rules import apply_rules
from logger.alert_manager import send_alert
from detection.feature_extraction import extract_features
from detection.feature_store import store_features, get_aggregated_features
from detection.baseline import update_baseline
from detection.anomaly_detection import detect_anomalies
from detection.alert_suppressor import should_suppress
conf.use_pcap = True

def process_packet(packet):
    parsed_data = {}


    for parser in (
        parse_ethernet_packet,
        parse_ip_packet,
        parse_tcp_packet,
        parse_udp_packet,
        parse_icmp_packet
    ):

        data = parser(packet)
        if data:
            parsed_data.update(data)
    ##print("[DEBUG] Parsed packet:", parsed_data)


    if not parsed_data:
        return

    alerts = apply_rules(parsed_data)

    for alert in alerts:
        if should_suppress(alert):
            continue
        else:
            send_alert(alert)
    
    features = extract_features(parsed_data)
    if not features:
        return

    src_ip = features["src_ip"]

   
    store_features(src_ip, features)

    aggregated_features = get_aggregated_features(src_ip)
    if not aggregated_features:
        return

    anomaly_alerts = detect_anomalies(src_ip, aggregated_features)

    if not anomaly_alerts:
         update_baseline(src_ip, aggregated_features)

    for alert in anomaly_alerts:
        if should_suppress(alert):
            continue
        else:
            send_alert(alert)


def start_sniffer():
    print("[*] Sniffer started...")
    sniff(iface="wlan0",prn=process_packet, store=False)
