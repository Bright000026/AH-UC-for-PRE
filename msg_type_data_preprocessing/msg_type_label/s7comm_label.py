import csv

ROSCTR_LABELS = {
    0x01: "HELLO",
    0x02: "ACK_DATA",
    0x03: "REQUEST",
    0x04: "RESPONSE",
    0x05: "USER_DATA",
    0x06: "ACK",
}

def parse_s7comm_packet(hex_string):
    try:
        bytes_object = bytes.fromhex(hex_string)
    except ValueError:
        print(f"Skip invalid hexadecimal strings: {hex_string}")
        return None, None
    
    rosctr = bytes_object[8]
    
    label = f"ROSCTR_{rosctr}"

    if rosctr == 0x07:  # USER_DATA
        if len(bytes_object) < 17:
            print(f"Skip messages of insufficient length: {hex_string}")
            return label, hex_string
        
        Function = bytes_object[17]
        label += f"-Function_{Function}"
        
        if Function != 1:
        
            syntax_id = bytes_object[21]
            label += f"-SYNTAX_ID_{syntax_id}"
    
            # Type, Function Group, Sub Function 
            type_fg = bytes_object[22]
    
            sub_function = bytes_object[23] 
            
            label += f"-type_fg_{type_fg}-sub_function_{sub_function}"
            #print(label)
            if bytes_object[25] == 0:
                error_code = bytes_object[27:29]
                return_code = bytes_object[29]
            else:
                error_code = 0xff
                return_code = bytes_object[25]
            # Error Code and Return Code         
            if error_code != 0xff:
                label += f"-ERROR_CODE_{error_code}"
            if return_code is not None:
                label += f"-RETURN_CODE_{return_code}"
        else:
            current_mode = bytes_object[23]
            label += f"-current_mode_{current_mode}"

    elif len(bytes_object) > 9:
        if bytes_object[17] == 0:
            Function = bytes_object[19]
        else:
            Function = bytes_object[17]
        label += f"-FUNCTION_{Function}"
        
        """
        if len(bytes_object) > 11:
            job = bytes_object[10]
            acknowledge = bytes_object[11]
            label += f"-JOB_{job}-ACK_{acknowledge}"
            
        # Error Code and Return Code 
        if len(bytes_object) > 12:
            error_code = bytes_object[12]
            return_code = bytes_object[13] if len(bytes_object) > 13 else None
            
            if error_code != 0:
                label += f"-ERROR_CODE_{error_code}"
            if return_code is not None:
                label += f"-RETURN_CODE_{return_code}"
        """
    return label, hex_string

def parse_s7comm_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        hex_string = packet.strip()
        label, hex_str = parse_s7comm_packet(hex_string)
        if label is not None:
            parsed_data.append((hex_str, label))

    return parsed_data

def write_to_csv(parsed_data, output_file='s7comm_labeled.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"])  
        writer.writerows(parsed_data)

if __name__ == "__main__":
    input_file = 'F:\\s7comm.txt'
    output_file = 'F:\\s7comm.csv'

    parsed_data = parse_s7comm_packets(input_file)
    
    write_to_csv(parsed_data, output_file)