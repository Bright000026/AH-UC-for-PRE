# -*- coding: utf-8 -*-
"""
Created on Wed Jan 15 23:34:27 2025

@author: zml10
"""

import csv

# 读取处理后的CSV文件
with open('dnp3_deal.csv', 'r', newline='') as infile:
    reader = csv.reader(infile)
    rows = list(reader)  # 将所有行读取到列表中

# 初始化两个列表，用于存放每一组的第三行和第一行
third_rows = []  # 存放每一组的第三行
first_rows = []  # 存放每一组的第一行

# 每三行为一组进行处理
i = 0
while i < len(rows):
    group = rows[i:i+3]  # 获取当前组的三行数据
    if len(group) == 3:  # 确保当前组有三行
        # 提取第三行并转换为数值列表
        third_row = group[2]
        try:
            # 将第三行的每个值转换为整数
            third_row_numeric = [int(value) for value in third_row]
            # 找到最小值
            min_value = min(third_row_numeric)
            # 减去最小值
            third_row_normalized = [value - min_value for value in third_row_numeric]
            # 将处理后的第三行存入列表
            third_rows.append(third_row_normalized)
        except ValueError:
            # 如果转换失败（例如非数字字段），则跳过该组
            print(f"跳过第 {i//3 + 1} 组，因为第三行包含非数字字段: {third_row}")
            third_rows.append(third_row)  # 保持原始数据
        # 存入第一行
        first_rows.append(group[0])
    i += 3  # 移动到下一组

# 将两个列表组合成一个新的数据结构
combined_data = []
for index, (third_row, first_row) in enumerate(zip(third_rows, first_rows)):
    combined_data.append([index, third_row, first_row])

# 将结果写入新的CSV文件
with open('extracted_data.csv', 'w', newline='') as outfile:
    writer = csv.writer(outfile)
    # 写入表头
    writer.writerow(['Index', 'Third Row (Normalized)', 'First Row'])
    # 写入数据
    for row in combined_data:
        writer.writerow(row)