from scapy.all import *
import os

def parse_dhcp_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        hex_string = packet.strip()
        
        try:
            bytes_object = bytes.fromhex(hex_string)
        except ValueError:
            continue
        
        op = bytes_object[0]
        
        dhcp_options = bytes_object[240:]
        dhcp_message_type = None
        
        i = 0
        while i < len(dhcp_options):
            option_code = dhcp_options[i]
            if option_code == 0xFF:  # End of DHCP options
                break
            elif option_code == 0:   # Pad option
                i += 1
                continue
            
            length = dhcp_options[i + 1]
            if option_code == 53 and length == 1:  # DHCP Message Type
                dhcp_message_type = dhcp_options[i + 2]
                break
            i += length + 2  # Move to the next option
        
        if dhcp_message_type is None:
            print(f"The DHCP message type field is not found: {hex_string}")
            continue
        
        label = f"{'request' if op == 1 else 'reply'}-{dhcp_message_type}"
        
        parsed_data.append((hex_string, label))

    return parsed_data

if __name__ == "__main__":
    file_path = 'dhcp_3000.txt'
    parsed_data = parse_dhcp_packets(file_path)

    # Save parsed data to CSV
    import csv
    with open('dhcp_3000.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Hex String', 'Label'])
        writer.writerows(parsed_data)