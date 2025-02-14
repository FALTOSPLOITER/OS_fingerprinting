import pyshark
import os

def get_os_fingerprint(packet):
    # Extract relevant fields from the packet
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    src_port = packet.tcp.srcport
    dst_port = packet.tcp.dstport
    ttl = packet.ip.ttl
    window_size = packet.tcp.window_size
    mss = packet.tcp.options.mss
    timestamp = packet.tcp.options.timestamp

    # Perform OS fingerprinting based on the extracted fields
    if src_port == 80 or dst_port == 80:
        return "HTTP traffic suggests Windows or Linux"
    elif src_port == 443 or dst_port == 443:
        return "HTTPS traffic suggests Windows or Linux"
    elif src_port == 22 or dst_port == 22:
        return "SSH traffic suggests Linux"
    elif src_port == 23 or dst_port == 23:
        return "Telnet traffic suggests Linux"
    elif src_port == 53 or dst_port == 53:
        return "DNS traffic suggests Linux or Windows"
    elif ttl == 64:
        return "TTL of 64 suggests Linux or Unix"
    elif ttl == 128:
        return "TTL of 128 suggests Windows"
    elif window_size == 65535:
        return "Large window size suggests Windows"
    elif mss == 1460:
        return "MSS of 1460 suggests Windows"
    elif timestamp is not None:
        return "Timestamp option suggests Linux"
    else:
        return "Unknown OS"

def analyze_pcap_file(pcap_file):
    # Open the Wireshark pcap file
    capture = pyshark.FileCapture(pcap_file)

    # Analyze each packet in the pcap file
    for packet in capture:
        os_fingerprint = get_os_fingerprint(packet)
        print(f"Packet from {packet.ip.src} to {packet.ip.dst}: {os_fingerprint}")

    capture.close()

def analyze_live_traffic():
    # Open a live capture using pyshark
    capture = pyshark.LiveCapture(interface='eth0')

    # Analyze each packet in the live capture
    for packet in capture.sniff_continuously():
        os_fingerprint = get_os_fingerprint(packet)
        print(f"Packet from {packet.ip.src} to {packet.ip.dst}: {os_fingerprint}")

    capture.close()

# Main function
def main():
    print("OS Fingerprinting Tool")
    print("BY: NITHIEN AACHINTHYA")
    print("1. Analyze from Wireshark pcap file")
    print("2. Analyze live network traffic")

    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        pcap_file = input("Enter the path to the Wireshark pcap file: ")
        analyze_pcap_file(pcap_file)
    elif choice == '2':
        analyze_live_traffic()
    else:
        print("Invalid choice. Exiting.")

if __name__ == '__main__':
    main()
