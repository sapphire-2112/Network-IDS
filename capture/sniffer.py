from scapy.all import sniff, conf
from parsers.ip import parse_ip_packet
from parsers.tcp import parse_tcp_packet
from parsers.udp import parse_udp_packet
from parsers.icmp import parse_icmp_packet
from parsers.ethernet import parse_ethernet_packet
from detection.portscan import detect_port_scan
from detection.icmp_sweep import detect_icmp_sweep

conf.use_pcap = True

def process_packet(packet):
    parsed_data = {}

    # Layer-wise parsing (bottom → top)
    eth = parse_ethernet_packet(packet)
    if eth:
        parsed_data.update(eth)

    ip = parse_ip_packet(packet)
    if ip:
        parsed_data.update(ip)

    tcp = parse_tcp_packet(packet)
    if tcp:
        parsed_data.update(tcp)
        detect_port_scan(parsed_data)

    udp = parse_udp_packet(packet)
    if udp:
        parsed_data.update(udp)

    icmp = parse_icmp_packet(packet)
    if icmp:
        parsed_data.update(icmp)
        detect_icmp_sweep(parsed_data)

    # Send parsed data to detection engine
    if parsed_data:
        detect_port_scan(parsed_data)

def start_sniffer():
    """
    Starts live packet capture.
    """
    print("[*] Sniffer started...")
    sniff(prn=process_packet, store=False)
