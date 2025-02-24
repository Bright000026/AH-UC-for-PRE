import json
import csv
import glob
import os


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
                    if k[:len(protocol_name) + 1] == protocol_name + '.':
                        # 如果字段名称以协议名称开头，则添加到字段名称、字段值和字段偏移位置列表
                        field_name_list.append(k)
                        packet_field_value_list.append(v[0])
                        packet_field_offset_list.append(v[1])  # 字段偏移位置
                        packet_byte_shift = v[1]
                        last_field_len = v[2]
                elif isinstance(protocol_name, list):
                    for name in protocol_name:
                        if k[:len(name) + 1] == name + '.':
                            field_name_list.append(k)
                            packet_field_value_list.append(v[0])
                            packet_field_offset_list.append(v[1])  # 字段偏移位置
                            packet_byte_shift = v[1]
                            last_field_len = v[2]

        # 处理重复键的情况
        if isinstance(v, list) and isinstance(v[0], list):
            for i in range(len(v)):
                if len(v[i]) == 5 and isinstance(v[i][0], str):
                    if v[i][1] == packet_byte_shift and v[i][2] == last_field_len:
                        last_field_len = v[i][2]
                        continue
                    else:
                        if isinstance(protocol_name, str):
                            if k[:len(protocol_name) + 1] == protocol_name + '.':
                                field_name_list.append(k)
                                packet_field_value_list.append(v[i][0])
                                packet_field_offset_list.append(v[i][1])  # 字段偏移位置
                                packet_byte_shift = v[i][1]
                                last_field_len = v[i][2]
                        elif isinstance(protocol_name, list):
                            for name in protocol_name:
                                if k[:len(name) + 1] == name + '.':
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


def read_pcap_json_file(json_filepath, csv_filepath, protocol_name):
    """
    读取 PCAP 文件的 JSON 数据，提取字段名称、字段值和字段偏移位置，并写入 CSV 文件。
    """
    with open(json_filepath, 'r', encoding='UTF-8') as pcap_json_file:
        pcap_data = json.load(pcap_json_file, object_pairs_hook=obj_pairs_hook)
        packet_number = len(pcap_data)

        packet_results = []  # 存储所有数据包的解析结果

        # 遍历每个数据包
        for i in range(packet_number):
            field_name_list = []  # 当前数据包的字段名称列表
            field_value_list = []  # 当前数据包的字段值列表
            field_offset_list = []  # 当前数据包的字段偏移位置列表

            packet_byte_shift = 0
            last_field_len = 0

            # 读取当前数据包的字段名称、字段值和字段偏移位置
            read_field(pcap_data[i], field_name_list, field_value_list, field_offset_list, packet_byte_shift, protocol_name, last_field_len)

            # 将字段偏移位置调整为从 0 开始
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

        # 将所有数据包的解析结果写入 CSV 文件
        write_csv(csv_filepath, packet_results)


def pcapjson2csv(protocol_name_list):
    """
    将指定协议的所有 JSON 文件转换为 CSV 文件。
    """
    for protocol_name in protocol_name_list:
        # 查找指定协议的所有 JSON 文件
        jsonfile_path_list = glob.glob(os.path.join('..', 'data', 'json', protocol_name, '*.json'), recursive=True)

        # 创建 CSV 文件的输出目录
        protocol_pcapcsvfolder_path = os.path.join('..', 'data', 'pcapcsv', protocol_name)
        if not os.path.exists(protocol_pcapcsvfolder_path):
            os.makedirs(protocol_pcapcsvfolder_path)

        # 处理 modbus 协议的特殊情况
        if protocol_name == 'modbus':
            protocol_name = ['mbtcp', 'modbus']

        # 遍历每个 JSON 文件并转换为 CSV 文件
        for json_filepath in jsonfile_path_list:
            file_name, _ = os.path.splitext(os.path.basename(json_filepath))
            csvfile_path = os.path.join(protocol_pcapcsvfolder_path, file_name + '.csv')
            read_pcap_json_file(json_filepath, csvfile_path, protocol_name)