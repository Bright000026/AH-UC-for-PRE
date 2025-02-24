from scapy.all import *
import os

def is_s7comm_packet(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return False
    
    try:
        if packet[TCP].dport != 102 and packet[TCP].sport != 102:
            return False
        
        payload = raw(packet[TCP].payload)
        if payload[7] != 0x32:
            return False
        if len(payload) >= 5: 
            return True
        
    except Exception as e:
        print(f"Error checking for S7COMM: {e}")
    
    return False

def extract_s7comm_data(packet):

    s7comm_data = b""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = raw(packet[TCP].payload)
        s7comm_data += payload
    return s7comm_data

def extract_s7comm_packets(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    s7comm_packets = []

    for packet in packets:
        if not is_s7comm_packet(packet):
            continue
        
        s7comm_message = extract_s7comm_data(packet)
        s7comm_packets.append(s7comm_message)

    with open(output_file, 'w') as f:
        for packet in s7comm_packets:
            f.write(packet.hex() + '\n')

if __name__ == "__main__":
    pcap_file = 's7_longer.pcap'
    output_file = 's7comm_longer.txt'

    extract_s7comm_packets(pcap_file, output_file)