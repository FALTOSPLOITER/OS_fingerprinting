import scapy.all as scapy
from scapy.layers.inet import IP, TCP, ICMP

# Function to perform OS fingerprinting based on TTL value
def os_fingerprint(ttl_value):
    # Common TTL values for different OS
    os_ttl_mapping = {
        64: "Linux, MacOS, or modern Windows",
        128: "Windows XP and above",
        255: "Cisco routers",
        49: "Solaris",
        255: "FreeBSD",
    }
    
    # Return the OS based on TTL value
    return os_ttl_mapping.get(ttl_value, "Unknown OS")

# Function to analyze a captured packet
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ttl = packet[IP].ttl
        print(f"Source IP: {ip_src} | TTL: {ttl} | OS: {os_fingerprint(ttl)}")

    if packet.haslayer(ICMP):
        print(f"ICMP Packet: {packet.summary()}")

    if packet.haslayer(TCP):
        print(f"TCP Packet: {packet.summary()}")

# Function to capture packets
def capture_packets(interface="eth0"):
    print("Starting packet capture...")
    scapy.sniff(iface=interface, prn=analyze_packet, store=False)

# Function to read pcap file for offline analysis
def read_pcap(pcap_file):
    print(f"Reading pcap file: {pcap_file}")
    packets = scapy.rdpcap(pcap_file)
    for packet in packets:
        analyze_packet(packet)

# Main function to capture live packets or read from a pcap file
def main():
    mode = input("Select mode (1 for live capture, 2 for offline pcap analysis): ")
    
    if mode == "1":
        interface = input("Enter network interface for packet capture (e.g., eth0): ")
        capture_packets(interface)
    elif mode == "2":
        pcap_file = input("Enter path to pcap file: ")
        read_pcap(pcap_file)
    else:
        print("Invalid mode selected!")

if __name__ == "__main__":
    main()
