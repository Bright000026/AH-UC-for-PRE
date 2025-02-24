from scapy.all import *
import os

def is_smb_packet(packet):
    if not packet.haslayer(TCP):
        return False
    try:
        payload = raw(packet[TCP].payload)
        message_length = int.from_bytes(payload[:4], byteorder='little')
        if message_length > 0 and payload[4:8] == b'\xffSMB':
            return True
    except Exception as e:
        print(f"Error checking for SMB2: {e}")
    return False


def extract_smb2_packets(pcap_file, client_file):
    packets = rdpcap(pcap_file)
    client_packets = []
    server_packets = []

    for packet in packets:
        if not is_smb_packet(packet):
            continue
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        smb_data = raw(packet[TCP].payload)[4:] 

        while smb_data:
            if b'\xffSMB' in smb_data[4:]:
                next_smb_index = smb_data[4:].index(b'\xffSMB')
                smb_packet = smb_data[:next_smb_index + 4]
                smb_data = smb_data[next_smb_index+4:]
            else:
                smb_packet = smb_data
                smb_data = 0
            client_packets.append(smb_packet)
            
    with open(client_file, 'w') as f:
        for packet in client_packets:
            f.write(packet.hex() + '\n')
   
    """
    with open(server_file, 'w') as f:
        for packet in server_packets:
            f.write(packet.hex() + '\n')
    """
if __name__ == "__main__":
    pcap_file = 'F:\\smb_1127.pcap'
    client_file = 'F:\\smb_1127.txt'

    extract_smb2_packets(pcap_file, client_file)