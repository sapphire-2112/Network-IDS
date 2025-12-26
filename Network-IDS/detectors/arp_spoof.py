arp_table={}
def detect_arp_spoof(packet):
    if packet.haslayer("ARP"):
        ip=packet["ARP"].psrc
        mac=packet["ARP"].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"\n🚨 [ALERT] ARP Spoofing Detected! IP {ip} is being claimed by multiple MAC addresses: {arp_table[ip]} and {mac}\n")

                arp_table[ip]=mac