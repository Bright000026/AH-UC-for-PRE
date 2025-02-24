from scapy.all import rdpcap, TCP
import struct

MODBUS_TCP_PORT = 502

def is_modbus_tcp_packet(packet):

    if not packet.haslayer(TCP) or packet[TCP].dport != MODBUS_TCP_PORT and packet[TCP].sport != MODBUS_TCP_PORT:
        return False
    if len(packet[TCP].payload) < 7:
        return False
    
    try:
        trans_id, proto_id, length = struct.unpack('!HHH', bytes(packet[TCP].payload)[:6])
        if proto_id == 0x0000 and length >= 1:
            return True
    except struct.error:
        return False
    
    return False

def extract_modbus_packets(pcap_file, output_file='modbus_packets.txt'):

    packets = rdpcap(pcap_file)
    modbus_records = []

    for packet in packets:
        if is_modbus_tcp_packet(packet):
            modbus_data = bytes(packet[TCP].payload)
            while len(modbus_data) >= 7:
                try:

                    trans_id, proto_id, length = struct.unpack('!HHH', modbus_data[:6])
                    unit_id = modbus_data[6]
                    pdu_length = length - 1  

                    if proto_id == 0x0000 and pdu_length >= 0:
       
                        modbus_pdu = modbus_data[:7 + pdu_length]
                        modbus_hex = modbus_pdu.hex()
                        modbus_records.append(modbus_hex)

                        modbus_data = modbus_data[7 + pdu_length:]
                    else:
                        break 
                except struct.error:
                    break 

    with open(output_file, 'w') as f:
        for hex_string in modbus_records:
            f.write(hex_string + '\n')


if __name__ == "__main__":
    input_pcap = 'ModbusTCP_1000.pcap'
    output_txt = 'ModbusTCP_1000.txt'

    extract_modbus_packets(input_pcap, output_txt)