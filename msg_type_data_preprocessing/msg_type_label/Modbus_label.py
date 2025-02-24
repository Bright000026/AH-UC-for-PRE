import csv

# Modbus Function Codes mapping for labeling (example, may need to be expanded based on actual needs)
FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers"
}

def parse_modbus_function_code(modbus_pdu):

    if len(modbus_pdu) < 8:
        return None, "Invalid PDU"

    function_code = modbus_pdu[7]
    label = function_code#FUNCTION_CODES.get(function_code, f"Unknown Function Code {function_code}")

    return function_code, label

def parse_modbus_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    labeled_records = []

    for packet in packets:
        hex_string = packet.strip()
        
        try:
            bytes_object = bytes.fromhex(hex_string)
        except ValueError:
            print(f"Skip invalid hexadecimal strings: {hex_string}")
            continue
        
        if len(bytes_object) < 8: #or int.from_bytes(bytes_object[1:3], byteorder='big') != 0x0000:
            print(f"Non-modbus /TCP packets or invalid packets are skipped: {hex_string}")
            continue
        
        function_code, label = parse_modbus_function_code(bytes_object)

        if function_code is not None:
            labeled_records.append((hex_string, label))

    return labeled_records

def write_to_csv(parsed_data, output_file='modbus_labeled.csv'):
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"])  
        writer.writerows(parsed_data)

if __name__ == "__main__":
    input_txt = '../label_format_cluster_data/modbus_new.txt'
    output_csv = '../label_format_cluster_data/modbus_new.csv'

    labeled_data = parse_modbus_packets(input_txt)
    
    write_to_csv(labeled_data, output_csv)
