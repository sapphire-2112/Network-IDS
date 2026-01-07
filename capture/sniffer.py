from scapy.all import sniff, conf
from datetime import datetime

from parsers.ip import parse_ip_packet
from parsers.tcp import parse_tcp_packet
from parsers.udp import parse_udp_packet
from parsers.icmp import parse_icmp_packet
from parsers.ethernet import parse_ethernet_packet

from detection.rules import apply_rules
from detection.feature_extraction import extract_features
from detection.feature_store import store_features, get_aggregated_features
from detection.baseline import update_baseline, get_baseline
from detection.anomaly_detection import detect_anomalies
from detection.alert_suppressor import should_suppress

from logger.alert_manager import send_alert
from ui.live_ui import add_packet

conf.use_pcap = True


def process_packet(packet):
    parsed = {}

    for parser in (
        parse_ethernet_packet,
        parse_ip_packet,
        parse_tcp_packet,
        parse_udp_packet,
        parse_icmp_packet,
    ):
        data = parser(packet)
        if data:
            parsed.update(data)

    if not parsed:
        return
    
    print("[DEBUG] Rule-based IDS executed")


    # ---- UI ----
    add_packet(parsed)

    # ---- RULE-BASED IDS (always active) ----
    for alert in apply_rules(parsed):
        if not should_suppress(alert):
            send_alert(alert)

    # ---- FEATURE PIPELINE ----
    features = extract_features(parsed)
    if not features:
        return

    src_ip = features["src_ip"]

    store_features(src_ip, features)
    aggregated = get_aggregated_features(src_ip)
    if not aggregated:
        return

    # ---- BASELINE GATE ----
    baseline_ready = False
    baseline_info = get_baseline(src_ip, "short", "packet_rate_avg")

    if baseline_info and not baseline_info.get("learning", True):
        baseline_ready = True

    if not baseline_ready:
        update_baseline(src_ip, aggregated)
        return

    # ---- ANOMALY DETECTION ----
    anomalies = detect_anomalies(src_ip, aggregated)

    if anomalies:
        for alert in anomalies:
            if not should_suppress(alert):
                send_alert(alert)
        return   # 🔥 freeze baseline during anomaly

    # ---- NORMAL TRAFFIC ----
    update_baseline(src_ip, aggregated)


def start_sniffer(interface="any"):
    print(f"[*] IDS started on {interface}")
    sniff(iface="any", prn=process_packet, store=False)
