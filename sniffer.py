from scapy.all import sniff, IP

# Callback function to process each packet
def process_packet(packet):
    if IP in packet:
        print("📦 New Packet:")
        print(f"➡ Source IP: {packet[IP].src}")
        print(f"⬅ Destination IP: {packet[IP].dst}")
        print(f"📡 Protocol: {packet[IP].proto}")
        print("-" * 50)

# Capture 10 packets (you can change the number or set to 0 for infinite)
sniff(count=10, prn=process_packet)


