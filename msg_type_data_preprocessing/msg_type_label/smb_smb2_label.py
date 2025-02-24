import csv

def parse_smb2_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        hex_string = packet.strip()
        
        if not hex_string.startswith('fe534d'):
            print(f"Non-smb2 packets are skipped: {hex_string}")
            continue
        
        bytes_object = bytes.fromhex(hex_string)
        
        command = bytes_object[12]
        
        flags_bit = 1 if (bytes_object[16] & 0x01) else 0
        
        if flags_bit == 1:
            nt_status = int.from_bytes(bytes_object[8:12], byteorder='little')
        else:
            nt_status = None
        
        label = f"{command}-{flags_bit}-{'0' if nt_status == 0 else 'non-zero'}" if flags_bit == 1 else f"{command}-{flags_bit}" 

        parsed_data.append((hex_string, label))

    return parsed_data

def parse_smb1_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        hex_string = packet.strip()
        
        if not hex_string.startswith('ff'):
            print(f"Non-smb1 packets are skipped: {hex_string}")
            continue
        
        try:
            bytes_object = bytes.fromhex(hex_string)
        except ValueError:
            print(f"Skip invalid hexadecimal strings: {hex_string}")
            continue

        command = bytes_object[4]
        
        flags_bit = 1 if (bytes_object[9] >> 7 ) else 0
        
        nt_status = None
        if flags_bit == 1:
            nt_status = int.from_bytes(bytes_object[5:9], byteorder='little')
        
        label = f"{command}-{flags_bit}-{'0' if nt_status == 0 else 'non-zero'}" if flags_bit == 1 else f"{command}-{flags_bit}"
        
        #label = f"{command}-{flags_bit}"

        parsed_data.append((hex_string, label))

    return parsed_data


def write_to_csv(parsed_data, output_file='smb2_5000.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"])  
        writer.writerows(parsed_data)

if __name__ == "__main__":
    output_file='smb2_pure.csv'
    parsed_data = parse_smb2_packets('smb2_pure.txt')
    
    write_to_csv(parsed_data,  output_file)