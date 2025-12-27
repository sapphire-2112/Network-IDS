from scapy.layers.inet import UDP

## ok now i will be getting Udp packets here..
def parse_udp_packet(packet):
    """
    UDP packet detected and parsed.
    """
    if UDP in packet:
        udp_layer = packet[UDP]
        return {
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "len": udp_layer.len,
        }
    return None
