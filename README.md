# OS Fingerprinting & Network Packet Capture Script

This Python script performs network packet capture and OS fingerprinting using the scapy library. It captures network packets in real-time or reads offline packet capture (.pcap) files and analyzes the data, focusing on identifying the operating system (OS) of the remote device based on its network behavior.

The OS fingerprinting is based on the TTL (Time to Live) value found in the IP header of the captured packets. Additionally, the script provides basic information about ICMP and TCP packets captured during the analysis.

# Features
Live Packet Capture: Captures network traffic in real-time on the specified network interface.
Offline Packet Analysis: Reads and analyzes packets from saved .pcap files.
OS Fingerprinting: Infers the operating system of a remote device based on the TTL value in the IP header.
Packet Summary: Provides details about captured packets, including IP, TCP, and ICMP layer information.
# Prerequisites
Python 3.x is required.
Scapy library is required for packet capture and analysis.
You can install Scapy using pip:


pip install scapy
Script Description
1. os_fingerprint(ttl_value):
This function takes the TTL value from a packet's IP header and maps it to a possible operating system.
The TTL values for some common operating systems are:
64: Linux, MacOS, or modern Windows
128: Windows XP and above
255: Cisco routers, FreeBSD
49: Solaris
Returns the OS based on the TTL value, or "Unknown OS" if the value doesn't match any known patterns.
2. analyze_packet(packet):
Analyzes the captured packet to extract information such as:
IP layer: Extracts the source IP and TTL value.
ICMP layer: If the packet is an ICMP packet, it prints a summary.
TCP layer: If the packet is a TCP packet, it prints a summary.
Calls os_fingerprint() to guess the operating system based on the TTL value.
3. capture_packets(interface="eth0"):
Captures live packets on the specified network interface (default is eth0).
Uses scapy.sniff() to continuously capture packets and pass them to analyze_packet() for processing.
4. read_pcap(pcap_file):
Reads offline .pcap files and processes each packet using analyze_packet().
5. main():
Prompts the user to select between live packet capture or offline packet analysis.
If live capture is selected, the user is asked for the network interface to capture from (e.g., eth0 or wlan0).
If offline analysis is selected, the user is asked to provide the path to a .pcap file.
Usage
Live Packet Capture:

Run the script and select option 1 for live packet capture.
Enter the network interface (e.g., eth0 for wired or wlan0 for wireless).
The script will begin capturing packets and analyzing them.
Offline Packet Analysis:

Select option 2 to analyze a saved .pcap file.
Provide the path to the .pcap file to read the packets and analyze them.
Example Output
Live Capture Mode:
yaml

Select mode (1 for live capture, 2 for offline pcap analysis): 1
Enter network interface for packet capture (e.g., eth0): eth0
Starting packet capture...
Source IP: 192.168.1.101 | TTL: 64 | OS: Linux, MacOS, or modern Windows
ICMP Packet: ICMP Echo Request 192.168.1.101 > 192.168.1.1
TCP Packet: TCP 192.168.1.101:443 > 192.168.1.1:56321 [SYN]
Source IP: 192.168.1.102 | TTL: 128 | OS: Windows XP and above
TCP Packet: TCP 192.168.1.102:80 > 192.168.1.1:56322 [ACK]
Offline Analysis Mode:
yaml

Select mode (1 for live capture, 2 for offline pcap analysis): 2
Enter path to pcap file: capture.pcap
Reading pcap file: capture.pcap
Source IP: 192.168.1.101 | TTL: 64 | OS: Linux, MacOS, or modern Windows
ICMP Packet: ICMP Echo Request 192.168.1.101 > 192.168.1.1
TCP Packet: TCP 192.168.1.101:443 > 192.168.1.1:56321 [SYN]
Source IP: 192.168.1.102 | TTL: 128 | OS: Windows XP and above
TCP Packet: TCP 192.168.1.102:80 > 192.168.1.1:56322 [ACK]
# Advanced Features
This script provides basic OS fingerprinting and packet analysis. However, for more accurate and advanced OS fingerprinting, consider integrating tools such as Nmap or p0f, which provide more reliable results based on multiple network characteristics.

You can also enhance the script to analyze additional packet fields, such as TCP window size, sequence numbers, or ICMP rate-limiting, for more granular information about the remote machine.

# Notes
Permissions: Running this script to capture live packets may require administrator/root permissions.
Network Interface: Ensure that the specified network interface (eth0, wlan0, etc.) is valid on your system and that you have access to it.
Packet Capture: Capturing packets on a busy network may result in large amounts of data. You can save packets to a .pcap file for offline analysis if necessary.
