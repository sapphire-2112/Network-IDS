from scapy.all import sniff,IP,TCP,UDP,ARP
from detectors.port_scan import *
def packet_callback(packet):
    if(packet.haslayer(IP)):
        src=packet[IP].src
        dst=packet[IP].dst
        print(f"[IP] {src} -> {dst}")

    if(packet.haslayer(TCP)):
        sport=packet[TCP].sport
        dport=packet[TCP].dport
        print(f"[TCP] {src}:{sport} -> {dst}:{dport}")
        detect_port_scan(packet)

    if(packet.haslayer(UDP)):
        print("UDP packet detected")

    if(packet.haslayer(ARP)):
        print(f"[ARP] who has {packet[ARP].pdst}? tell {packet[ARP].psrc}")

 

def start_ids():
    print("We are on the way to Start IDS......")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_ids()