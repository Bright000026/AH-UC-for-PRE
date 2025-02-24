from scapy.all import rdpcap, TCP

def is_ftp_packet(packet):

    if not packet.haslayer(TCP):
        return False
    try:
       
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            payload = bytes(packet[TCP].payload)
            if payload:  
                return True
    except Exception as e:
        print(f"Error checking for FTP: {e}")
    return False

def extract_ftp_packets(pcap_file, client_file):
    packets = rdpcap(pcap_file)
    ftp_packets = []

    for packet in packets:
        if not is_ftp_packet(packet):
            continue

        ftp_data = bytes(packet[TCP].payload)
        ftp_packets.append(ftp_data)

    with open(client_file, 'w') as f:
        for packet in ftp_packets:
            f.write(packet.hex() + '\n')

if __name__ == "__main__":
    pcap_file = 'ftp_pure.pcap'
    client_file = 'ftp.txt'

    extract_ftp_packets(pcap_file, client_file)