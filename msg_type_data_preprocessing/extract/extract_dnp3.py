from scapy.all import *
import os


def is_dnp3_packet(packet):
    # DNP3 typically runs over TCP on port 20000, but it can be configured to use other ports.
    if packet.haslayer(TCP) and (packet[TCP].dport == 20000 or packet[TCP].sport == 20000):
        try:
            payload = raw(packet[TCP].payload)
            # Check for the presence of the DNP3 start byte (0x0564 in network byte order)
            if len(payload) >= 2 and int.from_bytes(payload[:2], byteorder='big') == 0x0564:
                return True
        except Exception as e:
            print(f"Error checking for DNP3: {e}")
    return False

def has_application_layer_data(dnp3_payload):
    """
    Check if the DNP3 payload contains application layer data by verifying the presence of a non-zero length field.
    Additionally, check for the existence of a function code at the expected position.
    """
    # Length field is after the start byte (2 bytes) and control fields (2 bytes)
    length_field = int.from_bytes(dnp3_payload[4:6], byteorder='big')
    
    # If the length field indicates no data, it's likely just a link-layer message
    if length_field <= 4:  # Adjust this threshold based on your specific requirements
        return False
    
    # Check for the presence of a function code (position depends on the DNP3 version and options)
    # For simplicity, we assume the function code is present if there's enough room for it
    if len(dnp3_payload) >= 12:  # Minimum length to contain a function code
        function_code = dnp3_payload[11]  # Function code is at offset 11 in the DNP3 payload
        if function_code != 0:  # Non-zero function code indicates application layer data
            return True
    return False

def extract_dnp3_data(packet):
    # Extract only the DNP3-related data from the packet
    dnp3_data = b""
    if packet.haslayer(TCP):
        payload = raw(packet[TCP].payload)
        # Skip the first two bytes which are the start byte and length
        #if len(payload) > 2:
        dnp3_data += payload[:]
    return dnp3_data

def extract_dnp3_packets(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    dnp3_packets = []

    for packet in packets:
        if not is_dnp3_packet(packet):
            continue
        
        payload = raw(packet[TCP].payload)
        
        # Only process packets with application layer data
        if has_application_layer_data(payload):
            # Extract only the DNP3 message part
            dnp3_message = extract_dnp3_data(packet)
            
            # Append the DNP3 message to the list
            dnp3_packets.append(dnp3_message)

    # Save to file
    with open(output_file, 'w') as f:
        for packet in dnp3_packets:
            f.write(packet.hex() + '\n')

if __name__ == "__main__":
    pcap_file = 'dnp3_1500.pcap'
    output_file = 'dnp3_1500.txt'

    extract_dnp3_packets(pcap_file, output_file)