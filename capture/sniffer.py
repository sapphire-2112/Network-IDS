from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP

conf.use_pcap = True

def process_packet(packet):
    print("PACKET CAPTURED")
    if packet.haslayer(IP):
        print(f"Source: {packet[IP].src} -> Destination: {packet[IP].dst}")
        if packet.haslayer(TCP):
            print(f"Protocol: TCP | Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
                print(f"Protocol: UDP | Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")

    if packet.haslayer("ARP"):
        print("Common It's a Layer 2 ARP Packet")


def capture_packet():
    print("[*] Sniffer started...")
    sniff(count=10,prn=process_packet, store=False)

# START THE SNIFFER
capture_packet()
