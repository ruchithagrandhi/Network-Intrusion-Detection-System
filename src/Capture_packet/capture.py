from scapy.all import sniff, IP , TCP , UDP
from engine.rules import analyze_packet

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = None

        if TCP in packet:
            dst_port = packet[TCP].dport
        elif UDP in packet:
            dst_port = packet[UDP].dport

        analyze_packet(src_ip, dst_ip, dst_port)
def start_capture():
    print("[*] Starting packet capture...")
    sniff(filter="tcp", prn=packet_handler, store=False)

