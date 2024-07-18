import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"[+] New Packet: {src_ip} -> {dst_ip} (Protocol: {proto})")

        if proto == 6:  # TCP
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                print(f"    TCP Packet: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
        elif proto == 17:  # UDP
            if packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                print(f"    UDP Packet: {src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}")
        elif proto == 1:  # ICMP
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                print(f"    ICMP Packet: {src_ip} -> {dst_ip} (Type: {icmp_layer.type}, Code: {icmp_layer.code})")
        else:
            print(f"    Other IP Packet: {src_ip} -> {dst_ip} (Protocol: {proto})")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    scapy.sniff(prn=packet_callback, store=False)
