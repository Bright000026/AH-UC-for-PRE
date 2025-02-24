
from netzob.all import *
from src.netzob.Inference.Vocabulary.FormatOperations.ClusterByAlignment import ClusterByAlignment
from src.netzob.Inference.Vocabulary.FormatOperations.FieldSplitAligned import FieldSplitAligned
import binascii

with open('unknow2.txt', 'r', encoding='utf-8') as file:
    lines = file.readlines()

# 现在lines是一个列表，其中每个元素都是文件中的一行（包含换行符'\n'）
# 如果你想去除每行末尾的换行符，可以使用strip()方法
lines = [line.strip().encode() for line in lines]
samples = lines

messages = [RawMessage(data=sample[:50]) for sample in samples]
symbol = Symbol(messages=messages)
#symbol.addEncodingFunction(TypeEncodingFunction(HexaString))
#print(symbol.str_data())

"""
messages = [RawMessage(data=line) for line in lines[:5] ]
"""
clustering = ClusterByAlignment()
symbols = clustering.cluster(messages)
print(len(symbols))

with open("cluster_res.txt", "w") as f:
    for cluster_num in symbols:
        f.write("\n+++++++++++++++++++++++++++++++++++++++++++++++++\n")
        f.write(cluster_num.str_data())
#print(symbols[0].str_data())
