from scapy.layers.inet import IP

## ok now i will be getting Ip packets here..
def parse_ip_packet(packet):
    """
    IP packet detected and parsed.
    """
    if IP in packet:
        ip_layer = packet[IP]
        return {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "len": ip_layer.len,
            "proto": ip_layer.proto,
        }
    return None
