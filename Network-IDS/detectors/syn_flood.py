from collections import defaultdict
syn_count = defaultdict(int)
ack_count = defaultdict(int)
def detect_syn_flood(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src=packet["IP"].src
        flag=packet["TCP"].flags
        if flag=='S':
            syn_count+=1
        if flag=='A':
            ack_count+=1
        
        if syn_count-ack_count>30:
            print("[ALERT] Possible SYN Flood from {src} ||| SYN Count : {syn_count}")


