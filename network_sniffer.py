from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        if TCP in packet:
            print(f"    Protocol       : TCP")
        elif UDP in packet:
            print(f"    Protocol       : UDP")
        else:
            print(f"    Protocol       : Other")
        if packet.haslayer("Raw"):
            print(f"    Payload        : {packet['Raw'].load}")

print("[*] Starting Network Sniffer...")
sniff(prn=packet_callback, count=10)
