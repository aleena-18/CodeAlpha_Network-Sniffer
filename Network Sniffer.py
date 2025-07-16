from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] IP Packet: {src} -> {dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"    Payload: {payload[:50]}...")  # First 50 bytes only

        print("-" * 60)

sniff(count=20, prn=analyze_packet)
