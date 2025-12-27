from scapy.layers.inet import TCP

## ok now i will be getting Tcp packets here..
def parse_tcp_packet(packet):
    """
    TCP packet detected and parsed.
    """
    if TCP in packet:
        tcp_layer = packet[TCP]
        return {
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "flags": str(tcp_layer.flags),  # important for SYN detection
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
        }
    return None
