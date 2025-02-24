from scapy.all import *
import os
import csv

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData"
}

TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished"
}
ALLOWED_HANDSHAKE_TYPES = {1, 2, 11, 12, 13, 14, 15, 16, 20}
def parse_tls_packets(file_path):

    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        hex_string = packet.strip()
        
        try:
            bytes_object = bytes.fromhex(hex_string)
        except ValueError:
            print(f"Skip invalid hexadecimal strings: {hex_string}")
            continue
        
        if len(bytes_object) < 5:
            print(f"Skip messages of insufficient length: {hex_string}")
            continue
        
        content_type = bytes_object[0]
        label = f"{content_type}"

        if content_type == 22: 
            if len(bytes_object) < 11:
                continue
            
            handshake_type = bytes_object[5]
            if handshake_type not in ALLOWED_HANDSHAKE_TYPES:
                continue            
            label += f"_{handshake_type}"
        
        parsed_data.append((hex_string, label))

    return parsed_data


def write_to_csv(parsed_data, output_file='tls_labeled.csv'):

    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"]) 
        writer.writerows(parsed_data)
        
if __name__ == "__main__":
    input_file = 'F:\\tls_1.2_no_ccs.txt'
    output_file = 'F:\\tls_1.2_no_ccs.csv'


    parsed_data = parse_tls_packets(input_file)
    
    write_to_csv(parsed_data, output_file)