import csv

def parse_dns_packets(file_path):
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
        
        header = bytes_object[:12]
        qr_flag = int.from_bytes(header[2:4])  
        answer_rr = int.from_bytes(header[6:8])
        auth_rr =int.from_bytes(header[8:10])        
        
        #query_type = int.from_bytes(bytes_object[12:14], byteorder='big')
        
        label = f"{qr_flag}-{answer_rr}-{auth_rr}"
        
        parsed_data.append((hex_string, label))

    return parsed_data


def write_to_csv(parsed_data, output_file='dns_packets.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"]) 
        writer.writerows(parsed_data)

if __name__ == "__main__":
    input_file = 'F:\\dns_1000_new.txt'  
    output_file = 'F:\\dns_1000_new.csv'  
    
    parsed_data = parse_dns_packets(input_file)
    
    write_to_csv(parsed_data, output_file)