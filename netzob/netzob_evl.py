from netzob.all import*
import csv 
import numpy as np
from sklearn import metrics
import os
import binascii
import netzob
from netzob.Inference.Vocabulary.FormatOperations.ClusterByAlignment import ClusterByAlignment

def read_data(filename):
    hex_strings = []  
    labels = []

    with open(filename, mode='r', newline='') as file:
        reader = csv.reader(file)
        next(reader) 

        for row in reader:
            if len(row) < 2:  
                continue
            
            hex_string, label = row[:2]

            
            hex_strings.append(hex_string)
            labels.append(label)

    hex_strings = hex_strings[:1000] 
    return hex_strings, labels

def create_directory_if_not_exists(path):
 
    if not os.path.exists(path):
        os.makedirs(path)

def write_hex_string_to_file(file_path, hex_string):
    with open(file_path, 'w+') as file:
        file.write(hex_string)  
        
def clear_directory(directory_path):
   
    if os.path.exists(directory_path):
      
        for root, dirs, files in os.walk(directory_path, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
############################################################             


def evaluate_clustering(true_labels, predicted_labels, beta=0.4):
    noise_label = -1
    non_noise_mask = [label != noise_label for label in predicted_labels]
    print("noise labels num:" , len(predicted_labels) - len(non_noise_mask))
    
  
    filtered_true_labels = [true_labels[i] for i, mask in enumerate(non_noise_mask) if mask]
    filtered_predicted_labels = [predicted_labels[i] for i, mask in enumerate(non_noise_mask) if mask]

    # Homogeneity, Completeness and V-Measure
    h, c, v = metrics.homogeneity_completeness_v_measure(filtered_true_labels, filtered_predicted_labels, beta=beta)
    
    print(f"Homogeneity: {h:.4f}")
    print(f"Completeness: {c:.4f}")
    print(f"V-Measure: {v:.4f}")    
    return h, c, v

def refine_clusters(labels):

    label_counts = Counter(labels)
    
    singleton_labels = {label for label, count in label_counts.items() if count == 1 and label != -1}
    
    refined_labels = [label if label not in singleton_labels else -1 for label in labels]
    
    return np.array(refined_labels)

def get_cluster_labels(symbols, messages):

    # Step 2: Extract messages and labels, build the label mapping using hash
    message_to_label = {}
    for label, symbol in enumerate(symbols):
        for message in symbol.messages:
            if message.data not in message_to_label:
                message_to_label[message.data] = label
            else:
                # Ensure duplicate messages have the same label as before
                existing_label = message_to_label[message.data]
                if existing_label != label:
                    raise ValueError("Duplicate message found with different cluster assignments.")

    # Step 3: Create a list of labels in the same order as the original messages,
    # handling duplicates by looking up their labels from message_to_label
    labels = []
    for m in messages:
        labels.append(message_to_label[m.data])

    return labels
############################################################
import tracemalloc,time
if __name__ =="__main__": 

    dir_name = "./input/"
    filename = "s7comm_1000_new"
    tracemalloc.start()
    file_path = dir_name + filename +".csv" 
    raw_data, true_labels = read_data(file_path)
    
    messages = [RawMessage(data = binascii.unhexlify(sample)) for sample in raw_data]
    print(len(messages))
    start_time = time.time()
    clustering = ClusterByAlignment()
    
    #messages = ["fe432d5678", "fe432d0099", "00ff221234", "00ff221234"]
    #messages = [RawMessage(data = binascii.unhexlify(sample)) for sample in messages]
    #clustering = netzob.FormatOperations.clusterByAlignment()
    symbols = clustering.cluster(messages)
    labels = get_cluster_labels(symbols, messages)
    end_time = time.time()
    print("time:",end_time - start_time)
    current, peak = tracemalloc.get_traced_memory()
    print(f"Current memory usage: {current / 1024 ** 2:.2f} MB")  
    print(f"Peak memory usage: {peak / 1024 ** 2:.2f} MB")
    print(f"{filename} clustering:",len(symbols))
    #print(labels)
    #evaluate_clustering(true_labels, labels, beta=0.4)
    evaluate_clustering(true_labels, labels, beta=0.4)
    #print(symbols)
    #print(symbols[0].str_data())
    
    