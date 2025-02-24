import csv

FTP_COMMAND_CODES = {
    b'USER': 'User',
    b'PASS': 'Password',
    b'QUIT': 'Quit',
    b'PORT': 'Port',
    b'PASV': 'Passive Mode',
    b'RETR': 'Retrieve File',
    b'STOR': 'Store File',
    b'LIST': 'List Directory',
    b'CWD': 'Change Working Directory',
    b'PWD': 'Print Working Directory',
}

FTP_STATUS_CODES = {
    220: 'Service ready for new user',
    230: 'User logged in, proceed',
    331: 'User name okay, need password',
    425: 'Can not open data connection',
    530: 'Not logged in',
}

def parse_ftp_packet(hex_string):
    try:
        bytes_object = bytes.fromhex(hex_string)
    except ValueError:
        print(f"Skip invalid hexadecimal strings: {hex_string}")
        return None, None
    
    try:
        ftp_data = bytes_object.decode('ascii').strip()
    except UnicodeDecodeError:
        return None, None

    if ftp_data and ftp_data[0].isdigit() and len(ftp_data) >= 3:
        status_code = ftp_data[:3]
        label = f"{status_code}"
    else:

        alt_delim = ftp_data.find("\r\n")
        space_index = ftp_data.find(' ')
        if space_index == -1 or (alt_delim < space_index and space_index > 0):
            command_code = ftp_data.split('\r\n')[0] if alt_delim != -1 else ftp_data
        else:
            command_code = ftp_data.split(' ')[0] if space_index != -1 else ftp_data
        label = f"{command_code}"

    return hex_string, label

def parse_ftp_packets(file_path):
    with open(file_path, 'r') as file:
        packets = file.readlines()

    parsed_data = []

    for packet in packets:
        result = parse_ftp_packet(packet.strip())
        if result[1]:  
            parsed_data.append(result)

    return parsed_data

def write_to_csv(parsed_data, output_file='ftp_labeled.csv'):

    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Packet", "Label"])  
        writer.writerows(parsed_data)

if __name__ == "__main__":
    input_file = 'F:\\ftp.txt'
    output_file = 'F:\\ftp_labeled.csv'

    parsed_data = parse_ftp_packets(input_file)
    write_to_csv(parsed_data, output_file)