import csv

# DNP3 Function Codes mapping for labeling (example, may need to be expanded based on actual needs)
FUNCTION_CODES = {
    1: "DIRECT_OPERATE_NO_ACK",
    2: "DIRECT_OPERATE",
    3: "SELECT",
    4: "OPERATE",
    5: "INITIALIZE_APPLICATION_DATA",
    6: "START_APPLICATION_RESET",
    7: "STOP_APPLICATION_RESET",
    8: "SAVE_CONFIGURATION",
    9: "ENABLE_UNSOLICITED",
    10: "DISABLE_UNSOLICITED",
    # Add more mappings as needed...
}

def parse_dnp3_packets(file_path):
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
        
        if len(bytes_object) < 12 or int.from_bytes(bytes_object[:2], byteorder='big') != 0x0564:
            print(f"Non-dnp3 packets are skipped: {hex_string}")
            continue
        
        function_code = bytes_object[12]
        
        #label = FUNCTION_CODES.get(function_code, f"{function_code}")
        label = f"{function_code}"
        parsed_data.append((hex_string, label))

    return parsed_data

def write_to_csv(parsed_data, output_file='dnp3_labeled.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"])  
        writer.writerows(parsed_data)

if __name__ == "__main__":
    input_file = 'F:\\dnp3_1500.txt'
    output_file = 'F:\\dnp3_1500.csv'

    parsed_data = parse_dnp3_packets(input_file)

    write_to_csv(parsed_data, output_file)