# -*- coding: utf-8 -*-
"""
Created on Wed Jan 15 23:25:39 2025

@author: zml10
"""

import csv

# 读取CSV文件
with open('dnp3.csv', 'r', newline='') as infile:
    reader = csv.reader(infile)
    rows = list(reader)  # 将所有行读取到列表中

# 每三行为一组进行处理
i = 0
while i < len(rows):
    group = rows[i:i+3]  # 获取当前组的三行数据

    # 1. 判断第一行的H列是否为'dnp3.al.fragments_raw'
    if group[0][7] == 'dnp3.al.fragments_raw':
        # 删除这一列，并将后面的列依次往前提前一列
        for row in group:
            del row[7]

    # 2. 判断每三行的第J列的第二行是否为“3c0206”，且第三行的第K列为4
    if len(group[1]) > 9 and len(group[2]) > 10:  # 确保第二行有第10列，第三行有第11列
        if group[1][9] == '3c0206' and group[2][10] == '4':
            # 把第三行的第K列的4改为5
            group[2][10] = '5'

    # 3. 把每一组第三行中从第H列开始，每个数都加65
    for col in range(7, len(group[2])):
        try:
            group[2][col] = str(int(group[2][col]) + 65)
        except ValueError:
            # 如果无法转换为整数，则跳过（例如非数字字段）
            pass

    # 将处理后的组写回到原列表中
    rows[i:i+3] = group
    i += 3  # 移动到下一组

# 将处理后的数据写入新的CSV文件
with open('dnp3_deal.csv', 'w', newline='') as outfile:
    writer = csv.writer(outfile)
    writer.writerows(rows)