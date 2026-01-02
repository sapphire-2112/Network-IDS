import time
from collections import defaultdict
## Let's Extract Features From a Packet So actually We can create a baseline 
## As in the project I have tcp(port_scan) and icmp(icmp_sweep) detection rules implemented
## So features must be around it 
Time_window = 10

traffic_stats = defaultdict(lambda: {
    "start_time": time.time(),
    "packet_count": 0,
    "byte_count": 0,
    "ports": set(),
    "dest_ips": set(),
    "tcp_syn_count": 0,
    "icmp_count": 0
})

def extract_features(parsed_packet):
    src_ip=parsed_packet.get("src_ip")
    if not src_ip:
        return None
    now=time.time()
    stats=traffic_stats[src_ip]

    stats["packet_count"]+=1
    stats["byte_count"]+=parsed_packet.get("length",0)
    port=parsed_packet.get("dst_port")
    if port:
        stats["ports"].add(port)
    stats["dest_ips"].add(parsed_packet.get("dst_ip"))
    if parsed_packet.get("protocol")=="TCP" and parsed_packet.get("flags")=="S":
        stats["tcp_syn_count"]+=1
    elif parsed_packet.get("protocol")=="ICMP":
        stats["icmp_count"]+=1

    elapsed_time=now-stats["start_time"]
    if elapsed_time>=Time_window:
        features=get_features(src_ip,stats,elapsed_time)

        traffic_stats[src_ip]={
            "start_time": now,
            "packet_count": 0,
            "byte_count": 0,
            "ports": set(),
            "dest_ips": set(),
            "tcp_syn_count": 0,
            "icmp_count": 0
        }
        return features
    return None
def get_features(src_ip,stats,elapsed_time): 
   features={                                        ### Normalising the features 
   "src_ip" : src_ip,
   "packet_rate" : stats["packet_count"] / elapsed_time,
    "byte_rate" : stats["byte_count"] / elapsed_time,
    "unique_port_count" : len(stats["ports"]),
    "unique_dest_ip_count" : len(stats["dest_ips"]),
    "tcp_syn_rate" : stats["tcp_syn_count"] / elapsed_time,
    "icmp_rate" : stats["icmp_count"] / elapsed_time,
    "window_duration" : elapsed_time
   }
   return features
