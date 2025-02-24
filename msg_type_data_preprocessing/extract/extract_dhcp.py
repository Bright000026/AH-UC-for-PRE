from scapy.all import *
import os

def is_dhcp_packet(packet):
    if packet.haslayer(UDP) and packet.haslayer(BOOTP):
        # DHCP messages contain a specific field in the BOOTP layer
        # We can identify DHCP by checking for the presence of the 'options' field
        if packet[BOOTP].op == 1 or packet[BOOTP].op == 2:  # 1 = BOOTREQUEST, 2 = BOOTREPLY
            dhcp_layer = packet[BOOTP]
            if dhcp_layer.haslayer(DHCP):
                return True
    return False

def extract_dhcp_data(packet):
    # Extract only the DHCP-related data from the packet
    dhcp_data = b""
    if packet.haslayer(BOOTP) and packet.haslayer(DHCP):
        # Extract the BOOTP layer
        dhcp_data += raw(packet[BOOTP])
        # If there's more data after BOOTP (like DHCP options), append it too
        bootp_len = len(raw(packet[BOOTP]))
        udp_payload = raw(packet[UDP].payload)
        dhcp_data += udp_payload[bootp_len:]
    return dhcp_data

def extract_dhcp_packets(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    dhcp_packets = []

    for packet in packets:
        if not is_dhcp_packet(packet):
            continue
        
        # Extract only the DHCP message part
        dhcp_message = extract_dhcp_data(packet)
        
        # Append the DHCP message to the list
        dhcp_packets.append(dhcp_message)

    # Save to file
    with open(output_file, 'w') as f:
        for packet in dhcp_packets:
            f.write(packet.hex() + '\n')

if __name__ == "__main__":
    pcap_file = 'dhcp.pcap'
    output_file = 'dhcp_extracted.txt'

    extract_dhcp_packets(pcap_file, output_file)