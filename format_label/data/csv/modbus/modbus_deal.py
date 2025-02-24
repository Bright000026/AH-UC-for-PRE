# -*- coding: utf-8 -*-
"""
Created on Wed Jan 15 20:48:18 2025

@author: zml10
"""

import csv

def process_row(row):
    # 处理 Hex 列：删除头 14 个字符
    # hex_data = row[0]
    # if len(hex_data) >= 14:
    #     row[0] = hex_data[14:]  # 删除头 14 个字符

    # 处理 Segment 列和 Field Names 列
    segments = eval(row[1])  # 将字符串转换为列表
    field_names = eval(row[2])  # 将字符串转换为列表

    # 记录已经出现过的数字
    seen = set()
    new_segments = []
    new_field_names = []

    for i, segment in enumerate(segments):
        if segment not in seen:
            seen.add(segment)
            new_segments.append(segment)
            new_field_names.append(field_names[i])

    # 更新行数据
    row[1] = str(new_segments)
    row[2] = str(new_field_names)

    return row

def process_csv(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # 写入表头
        header = next(reader)
        writer.writerow(header)

        # 处理每一行
        for row in reader:
            processed_row = process_row(row)
            writer.writerow(processed_row)

# 输入文件和输出文件路径
input_file = 'modbus_new.csv'
output_file = 'modbus_new_deal.csv'

# 处理 CSV 文件
process_csv(input_file, output_file)

print(f"处理完成！结果已保存到 {output_file}")