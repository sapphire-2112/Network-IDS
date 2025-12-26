from scapy.layers.inet import ICMP
##ok now i will be getting Icmp packets here..
def parse_icmp_packet(packet):
    """
    ICMP packet detected and parsed.
    """
    if ICMP in packet:
        icmp_layer = packet[ICMP]
        parsed_data = {
            "type": icmp_layer.type,
            "code": icmp_layer.code,
            "chksum": icmp_layer.chksum,
            "id": icmp_layer.id,
            "seq": icmp_layer.seq,
        }
        return parsed_data
    return None