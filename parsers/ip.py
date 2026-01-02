from scapy.layers.inet import IP

def parse_ip_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        parsed = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "len": ip_layer.len,
            "proto": ip_layer.proto,
        }

        # ADD THIS
        if ip_layer.proto == 6:
            parsed["protocol"] = "TCP"
        elif ip_layer.proto == 1:
            parsed["protocol"] = "ICMP"
        elif ip_layer.proto == 17:
            parsed["protocol"] = "UDP"

        return parsed

    return None
