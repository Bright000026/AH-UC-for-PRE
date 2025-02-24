# -*- coding: utf-8 -*-
"""
Created on Mon Dec 23 15:13:41 2024

@author: Admin
"""

from scapy.all import *
import os


def is_tls_packet(packet):
    """
    检查数据包是否为TLS 1.2协议。
    TLS 1.2通常在TCP上运行，默认端口为443。
    """
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return False
    
    try:
        payload = raw(packet[TCP].payload)
        
        # TLS 1.2默认使用TCP端口443
        if packet[TCP].dport != 443 and packet[TCP].sport != 443:
            return False
        
        # TLS记录层头部是5个字节，第1个字节是内容类型(Content Type)，后2个字节是版本号(Version)
        # TLS 1.2的版本号是0x0303
        if len(payload) >= 5 and int.from_bytes(payload[1:3], byteorder='big') == 0x0303:
            return True
        
    except Exception as e:
        print(f"Error checking for TLS 1.2: {e}")
    
    return False

def extract_tls_records(packet, max_ccs=1, max_app_data=5):
    """
    提取并分割同一TCP段中的所有TLS记录，并过滤Change Cipher Spec和Application Data消息。
    """
    tls_records = []
    ccs_count = 0  # 记录Change Cipher Spec消息的数量
    app_data_count = 0  # 记录Application Data消息的数量
    payload = raw(packet[TCP].payload)

    while len(payload) >= 5:
        content_type = payload[0]
        version = int.from_bytes(payload[1:3], byteorder='big')
        length = int.from_bytes(payload[3:5], byteorder='big')

        if version != 0x0303 or len(payload) < length + 5:
            break

        record = payload[:length + 5]

        # 处理Change Cipher Spec消息
        if content_type == 20:
            if ccs_count < max_ccs:
                tls_records.append(record)
                ccs_count += 1
        elif content_type == 23:  # Application Data消息
            if app_data_count < max_app_data:
                tls_records.append(record)
                app_data_count += 1
        else:
            tls_records.append(record)

        payload = payload[length + 5:]

    return tls_records

def extract_tls_packets(pcap_file, output_file, max_ccs_per_packet=1, max_app_data_per_packet=5):
    """
    从PCAP文件中提取所有TLS 1.2协议的数据包，并保存到文本文件中。
    """
    packets = rdpcap(pcap_file)
    all_tls_records = []

    for packet in packets:
        if not is_tls_packet(packet):
            continue
        
        # 提取并分割TLS 1.2记录，同时过滤Change Cipher Spec和Application Data消息
        tls_records = extract_tls_records(packet, max_ccs=max_ccs_per_packet, max_app_data=max_app_data_per_packet)
        all_tls_records.extend(tls_records)

    # 保存到文件
    with open(output_file, 'w') as f:
        for record in all_tls_records:
            f.write(record.hex() + '\n')


if __name__ == "__main__":
    pcap_file = 'F:\\流量数据集\\tls1.2.pcap'
    output_file = 'F:\\流量数据集\\tls_1.2.txt'
    max_ccs_per_packet = 1
    max_app_data_per_packet = 2

    extract_tls_packets(pcap_file, output_file, max_ccs_per_packet, max_app_data_per_packet)