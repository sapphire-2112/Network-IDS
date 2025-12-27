from scapy.layers.l2 import Ether

## ok now i will be getting Ethernet packets here..
def parse_ethernet_packet(packet):
    """
    Ethernet packet detected and parsed.
    """
    if Ether in packet:
        eth_layer = packet[Ether]
        return {
            "src_mac": eth_layer.src,
            "dst_mac": eth_layer.dst,
            "type": eth_layer.type,  # tells which protocol is encapsulated
        }
    return None
