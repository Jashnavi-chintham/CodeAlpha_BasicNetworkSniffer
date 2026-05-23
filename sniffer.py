from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process packets
def packet_callback(packet):

    print("\n=== Packet Captured ===")

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")

        if packet.haslayer(TCP):
            print("Protocol Type: TCP")

        elif packet.haslayer(UDP):
            print("Protocol Type: UDP")

        else:
            print("Other Protocol")

        payload = bytes(packet.payload)

        if payload:
            print(f"Payload: {payload[:50]}")

print("Starting Network Sniffer...")

sniff(prn=packet_callback, store=False)