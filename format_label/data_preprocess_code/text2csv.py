import json
import csv
import os
import subprocess
from tempfile import NamedTemporaryFile
import glob


def process_txt(input_txt_filepath, output_txt_filepath, protocol_name):
    """
    将原始的 TXT 文件处理成符合 text2pcap 要求的格式。

    参数:
        input_txt_filepath (str): 原始 TXT 文件路径。
        output_txt_filepath (str): 处理后的 TXT 文件路径。
        protocol_name (str): 协议名称（如 'smb', 'dnp3'）。

    处理规则:
        1. 每行一条报文。
        2. 对于 SMB/SMB2 协议：
           - 计算报文字节长度。
           - 在报文前添加 NetBIOS 服务头（4 字节长度字段）。
           - 将报文每个字节之间添加空格。
           - 在行首添加偏移量（000000）。
        3. 对于 DNP3 协议：
           - 不需要添加长度字段。
           - 将报文每个字节之间添加空格。
           - 在行首添加偏移量（000000）。
    """
    with open(input_txt_filepath, 'r', encoding='UTF-8') as input_file, \
         open(output_txt_filepath, 'w', encoding='UTF-8') as output_file:
        for line in input_file:
            # 去掉换行符和空格
            hex_str = line.strip()
            if not hex_str:
                continue

            # 将报文每两个字符之间添加空格
            formatted_hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

            # 根据协议名称处理报文
            if protocol_name in ['smb', 'smb2']:
                # 计算报文字节长度
                smb_length = len(hex_str) // 2  # 每两个字符表示一个字节

                # 将长度转换为大端序的 4 字节十六进制字符串
                length_bytes = smb_length.to_bytes(4, byteorder='big')
                length_hex = ' '.join(f'{byte:02x}' for byte in length_bytes)

                # 构造符合 text2pcap 要求的行
                formatted_line = f"000000 {length_hex} {formatted_hex_str}\n"
            elif protocol_name == 'dnp3':
                # 对于 DNP3 协议，不需要添加长度字段
                formatted_line = f"000000 {formatted_hex_str}\n"
            else:
                # 其他协议的处理逻辑（可以根据需要扩展）
                formatted_line = f"000000 {formatted_hex_str}\n"

            # 写入输出文件
            output_file.write(formatted_line)

def write_csv(csv_filepath, packet_results):
    """
    将每个数据包的解析结果写入 CSV 文件。
    每个数据包占用 3 行：
    1. 字段语义（字段名称）
    2. 字段值
    3. 字段偏移位置（从 0 开始）
    """
    with open(csv_filepath, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        for result in packet_results:
            # 写入字段语义（字段名称）
            writer.writerow(result['field_names'])
            # 写入字段值
            writer.writerow(result['field_values'])
            # 写入字段偏移位置（从 0 开始）
            writer.writerow(result['field_offsets'])
            
def write_new_csv(csv_filepath, packet_results, original_hex_list, protocol_name, pcap_filepath=None):
    """
    将每条报文的原始十六进制、切割偏移列表和字段语义列表写入新的 CSV 文件。

    参数:
        csv_filepath (str): 新的 CSV 文件路径。
        packet_results (list): 数据包解析结果列表。
        original_hex_list (list): 原始十六进制报文列表（如果输入是 TXT 文件）。
        protocol_name (str): 协议名称（如 'smb', 'dnp3'）。
        pcap_filepath (str, optional): 如果输入是 PCAP 文件，提供 PCAP 文件路径。
    """
    with open(csv_filepath, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        # 写入表头
        writer.writerow(['Hex', 'Segment', 'Field Names'])

        # 如果输入是 PCAP 文件，从 PCAP 文件中提取目标协议的十六进制报文
        if pcap_filepath:
            # 使用 tshark 提取目标协议的十六进制报文
            command = f'tshark -r {pcap_filepath} -Y "{protocol_name}" -T fields -e data'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"tshark 执行失败: {result.stderr}")

            # 提取十六进制报文
            original_hex_list = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        # 遍历每条报文
        for i, result in enumerate(packet_results):
            # 获取原始十六进制报文
            if original_hex_list and i < len(original_hex_list):
                hex_str = original_hex_list[i]
            else:
                hex_str = "N/A"  # 如果没有原始十六进制报文，填充为 "N/A"

            # 获取切割偏移列表
            segment_list = result['field_offsets']

            # 获取字段语义列表
            field_names_list = result['field_names']

            # 写入一行数据
            writer.writerow([hex_str, segment_list, field_names_list])

def read_field(pcap_data, field_name_list, packet_field_value_list, packet_field_offset_list, packet_byte_shift, protocol_name, last_field_len):
    """
    递归读取 JSON 数据中的字段名称、字段值和字段偏移位置。
    """
    for k, v in pcap_data.items():
        # 如果值是字典，递归调用 read_field
        if isinstance(v, dict):
            last_field_len = read_field(v, field_name_list, packet_field_value_list, packet_field_offset_list, packet_byte_shift, protocol_name, last_field_len)
            continue

        # 处理字段值
        if isinstance(v, list) and len(v) == 5 and isinstance(v[0], str):
            # 如果字段值符合特定格式（长度为 5 且第一个元素是字符串）
            if v[1] == packet_byte_shift and v[2] == last_field_len:
                last_field_len = v[2]
                continue
            else:
                if isinstance(protocol_name, str):
                    if k.startswith(protocol_name + '.'):  # 匹配以协议名称开头的字段
                        field_name_list.append(k)
                        packet_field_value_list.append(v[0])
                        packet_field_offset_list.append(v[1])  # 字段偏移位置
                        packet_byte_shift = v[1]
                        last_field_len = v[2]
                elif isinstance(protocol_name, list):
                    for name in protocol_name:
                        if k.startswith(name + '.'):  # 匹配以协议名称开头的字段
                            field_name_list.append(k)
                            packet_field_value_list.append(v[0])
                            packet_field_offset_list.append(v[1])  # 字段偏移位置
                            packet_byte_shift = v[1]
                            last_field_len = v[2]

        # 处理嵌套字段（如 dnp3.hdr.CRC_raw）
        if isinstance(v, list) and len(v) == 5 and isinstance(v[0], list):
            for i in range(len(v)):
                if len(v[i]) == 5 and isinstance(v[i][0], str):
                    if v[i][1] == packet_byte_shift and v[i][2] == last_field_len:
                        last_field_len = v[i][2]
                        continue
                    else:
                        if isinstance(protocol_name, str):
                            if k.startswith(protocol_name + '.'):  # 匹配以协议名称开头的字段
                                field_name_list.append(k)
                                packet_field_value_list.append(v[i][0])
                                packet_field_offset_list.append(v[i][1])  # 字段偏移位置
                                packet_byte_shift = v[i][1]
                                last_field_len = v[i][2]
                        elif isinstance(protocol_name, list):
                            for name in protocol_name:
                                if k.startswith(name + '.'):  # 匹配以协议名称开头的字段
                                    field_name_list.append(k)
                                    packet_field_value_list.append(v[i][0])
                                    packet_field_offset_list.append(v[i][1])  # 字段偏移位置
                                    packet_byte_shift = v[i][1]
                                    last_field_len = v[i][2]
    return last_field_len

def obj_pairs_hook(lst):
    """
    处理 JSON 数据中的重复键。
    """
    result = {}
    count = {}
    for key, val in lst:
        if key in count:
            count[key] = 1 + count[key]
        else:
            count[key] = 1
        if key in result:
            if count[key] > 2:
                result[key].append(val)
            else:
                result[key] = [result[key], val]
        else:
            result[key] = val
    return result




def hex_to_pcap(text2pcap_input_filepath, pcap_filepath, protocol_name):
    """
    将 text2pcap 输入文件转换为 PCAP 文件。

    参数:
        text2pcap_input_filepath (str): text2pcap 输入文件路径。
        pcap_filepath (str): 输出的 PCAP 文件路径。
        protocol_name (str): 协议名称（如 'smb'）。

    根据协议名称动态生成 text2pcap 命令：
        - SMB 协议：使用 -T 139,445 指定端口。
        - 其他协议：使用默认命令。
    """
    # 根据协议名称动态生成 text2pcap 命令
    if protocol_name in ['smb', 'smb2']:
        # SMB 协议的命令
        command = f'text2pcap -T 139,445 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name == 'dnp3':
        # DNP3 协议的命令
        command = f'text2pcap -T 20000,20000 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name == 's7comm':
        command = f'text2pcap -T 102,102 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name == 'tls':
        command = f'text2pcap -T 443,443 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name == 'ftp':
        command = f'text2pcap -T 21,22 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name == 'dns':
        command = f'text2pcap -u 53,53 {text2pcap_input_filepath} {pcap_filepath}'
    elif protocol_name ==  'modbus':
        command = f'text2pcap -T 502,502 {text2pcap_input_filepath} {pcap_filepath}'
    else:
        # 其他协议的默认命令
        command = f'text2pcap {text2pcap_input_filepath} {pcap_filepath}'

    # 打印调试信息
    print(f"执行命令: {command}")  # 调试信息

    # 运行命令
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"text2pcap 执行失败: {result.stderr}")  # 调试信息
    else:
        print(f"text2pcap 执行成功")


def pcap_to_json(pcap_filepath, json_filepath, protocol_name):
    """
    将 PCAP 文件解析为 JSON 文件。
    """
    if protocol_name == 'modbus':
        command = f'tshark -r {pcap_filepath} -T json -O "mbtcp modbus" -x > {json_filepath}'
    else:
        command = f'tshark -r {pcap_filepath} -T json -O "{protocol_name}" -x > {json_filepath}'
    subprocess.run(command, shell=True)

def txt_to_csv(input_filepath, csv_filepath, protocol_name):
    """
    将 TXT 文件或 PCAP 文件中的报文转换为 CSV 文件。
    """
    packet_results = []  # 存储所有数据包的解析结果
    original_hex_list = []  # 存储原始十六进制报文

    # 判断输入文件是 TXT 还是 PCAP
    file_extension = os.path.splitext(input_filepath)[1].lower()

    if file_extension == '.txt':
        # 处理 TXT 文件
        process_txt_dir = os.path.join('process_txt')
        os.makedirs(process_txt_dir, exist_ok=True)

        # 处理 TXT 文件
        processed_txt_filepath = os.path.join(process_txt_dir, os.path.basename(input_filepath))
        process_txt(input_filepath, processed_txt_filepath, protocol_name)

        # 读取原始十六进制报文
        with open(input_filepath, 'r', encoding='UTF-8') as f:
            original_hex_list = [line.strip() for line in f if line.strip()]

        # 将处理后的 TXT 文件直接传递给 hex_to_pcap
        temp_pcap_dir = os.path.join('temp_pcap')  # PCAP 文件保存目录
        os.makedirs(temp_pcap_dir, exist_ok=True)  # 创建目录（如果不存在）
        pcap_filepath = os.path.join(temp_pcap_dir, f'{protocol_name}.pcap')  # 使用协议名称命名 PCAP 文件
        hex_to_pcap(processed_txt_filepath, pcap_filepath, protocol_name)  # 传入处理后的 TXT 文件

    elif file_extension == '.pcap':
        # 直接使用传入的 PCAP 文件
        print("直接使用pcap！")
        pcap_filepath = input_filepath

    else:
        raise ValueError("输入文件必须是 TXT 或 PCAP 文件")

    # 将 PCAP 文件解析为 JSON 文件
    json_filepath = 'temp.json'
    pcap_to_json(pcap_filepath, json_filepath, protocol_name)

    # 读取 JSON 文件
    with open(json_filepath, 'r', encoding='UTF-8') as f:
        json_data = json.load(f, object_pairs_hook=obj_pairs_hook)

    # 删除临时文件
    #os.remove(json_filepath)
    if protocol_name == 'modbus':
        protocol_name =['mbtcp', 'modbus']
    # 解析 JSON 数据
    for packet in json_data:
        field_name_list = []  # 当前数据包的字段名称列表
        field_value_list = []  # 当前数据包的字段值列表
        field_offset_list = []  # 当前数据包的字段偏移位置列表

        packet_byte_shift = 0
        last_field_len = 0

        read_field(packet, field_name_list, field_value_list, field_offset_list, packet_byte_shift, protocol_name, last_field_len)

        if protocol_name == 'dnp3':
            # DNP3 协议的特殊处理逻辑：直接使用原始偏移量
            if field_offset_list:
                # 打印原始偏移量列表
                print("原始 field_offset_list:", field_offset_list)

                # 将 field_offset_list 中的值转换为整数
                try:
                    field_offset_list = [int(offset, 16) if isinstance(offset, str) and offset.startswith('0x') else int(offset) for offset in field_offset_list]
                except (ValueError, TypeError) as e:
                    print(f"无法解析偏移量: {field_offset_list}")
                    print(f"错误信息: {e}")
                    continue
        else:
            # 其他协议的通用逻辑
            if field_offset_list:
                # 将 field_offset_list 中的值转换为整数
                try:
                    field_offset_list = [int(offset, 16) if isinstance(offset, str) and offset.startswith('0x') else int(offset) for offset in field_offset_list]
                except (ValueError, TypeError) as e:
                    print(f"无法解析偏移量: {field_offset_list}")
                    print(f"错误信息: {e}")
                    continue

                # 将字段偏移位置调整为从 0 开始
                first_offset = field_offset_list[0]  # 第一个字段的偏移值
                field_offset_list = [offset - first_offset for offset in field_offset_list]

        # 将当前数据包的解析结果添加到总列表中
        packet_results.append({
            'field_names': field_name_list,
            'field_values': field_value_list,
            'field_offsets': field_offset_list
        })
    if protocol_name == ['mbtcp', 'modbus']:
        protocol_name = 'modbus'
    # 将所有数据包的解析结果写入原始 CSV 文件
    write_csv(csv_filepath, packet_results)

    # 生成新的 CSV 文件
    new_csv_filepath = os.path.join(os.path.dirname(csv_filepath), f'{protocol_name}_new.csv')
    write_new_csv(new_csv_filepath, packet_results, original_hex_list, protocol_name, pcap_filepath if file_extension == '.pcap' else None)

def txt2csv(protocol_name_list):
    """
    将指定协议的所有 TXT 文件或 PCAP 文件转换为 CSV 文件。
    """
    for protocol_name in protocol_name_list:
        # 查找指定协议的所有 TXT 文件和 PCAP 文件
        txtfile_path_list = glob.glob(os.path.join('..', 'data', 'txt', protocol_name, '*.txt'), recursive=True)
        pcapfile_path_list = glob.glob(os.path.join('..', 'data', 'txt', protocol_name, '*.pcap'), recursive=True)

        # 创建 CSV 文件的输出目录
        protocol_csvfolder_path = os.path.join('..', 'data', 'csv', protocol_name)
        if not os.path.exists(protocol_csvfolder_path):
            os.makedirs(protocol_csvfolder_path)

        # 遍历每个 TXT 文件并转换为 CSV 文件
        for txt_filepath in txtfile_path_list:
            file_name, _ = os.path.splitext(os.path.basename(txt_filepath))
            csvfile_path = os.path.join(protocol_csvfolder_path, file_name + '.csv')
            txt_to_csv(txt_filepath, csvfile_path, protocol_name)

        # 遍历每个 PCAP 文件并转换为 CSV 文件
        for pcap_filepath in pcapfile_path_list:
            file_name, _ = os.path.splitext(os.path.basename(pcap_filepath))
            csvfile_path = os.path.join(protocol_csvfolder_path, file_name + '.csv')
            txt_to_csv(pcap_filepath, csvfile_path, protocol_name)


txt2csv(["dns"])