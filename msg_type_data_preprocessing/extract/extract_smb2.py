from scapy.all import *
import os

def is_smb2_packet(packet):
    if not packet.haslayer(TCP):
        return False
    try:
        payload = raw(packet[TCP].payload)
        message_length = int.from_bytes(payload[:4], byteorder='little')
        if message_length > 0 and payload[4:8] == b'\xfeSMB':
            return True
    except Exception as e:
        print(f"Error checking for SMB2: {e}")
    return False

def is_dcerpc_packet(packet):
    try:
        payload = raw(packet[TCP].payload)
        if b'\x05\x00\x0b\x03\x10\x00\x00\x00' in payload or b'\x05\x00\x0c\x03\x10\x00\x00\x00' in payload:
            return True
        return False
    except Exception as e:
        print(f"Error checking for DCERPC: {e}")
        return False

def extract_smb2_packets(pcap_file, client_file, server_file):
    packets = rdpcap(pcap_file)
    client_packets = []
    server_packets = []

    for packet in packets:
        if not is_smb2_packet(packet):
            continue
        if is_dcerpc_packet(packet):
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        smb2_data = raw(packet[TCP].payload)[4:] 

        while smb2_data:

            if b'\xfeSMB' in smb2_data[4:]:
                next_smb2_index = smb2_data[4:].index(b'\xfeSMB')
                smb2_packet = smb2_data[:next_smb2_index + 4]
                smb2_data = smb2_data[next_smb2_index+4:]
            else:
                smb2_packet = smb2_data
                smb2_data = 0
            client_packets.append(smb2_packet)

    with open(client_file, 'w') as f:
        for packet in client_packets:
            f.write(packet.hex() + '\n')

if __name__ == "__main__":
    pcap_file = 'smb2_pure.pcap'
    client_file = 'smb2_pure.txt'
    server_file = 'server_smb2_packets.txt'

    extract_smb2_packets(pcap_file, client_file, server_file)