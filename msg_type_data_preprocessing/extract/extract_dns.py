from scapy.all import rdpcap, DNS, UDP, IP, TCP
from scapy.all import *

def is_dns_packet(packet):
    return packet.haslayer(DNS)

def extract_dns_packets(pcap_file, output_file='dns_packets.txt'):
    packets = rdpcap(pcap_file)
    dns_hex_strings = []

    for packet in packets:
        if not is_dns_packet(packet):
            continue
        if packet.haslayer(UDP) or (packet.haslayer(TCP) and packet[TCP].dport == 53 or packet[TCP].sport == 53):
            dns_data = raw(packet[DNS])
            
            dns_hex_string = dns_data.hex()
            dns_hex_strings.append(dns_hex_string)

    with open(output_file, 'w') as f:
        for hex_string in dns_hex_strings:
            f.write(hex_string + '\n')

if __name__ == "__main__":
    pcap_file = 'dns.pcap'
    output_file = 'dns.txt'

    extract_dns_packets(pcap_file, output_file)