import numpy as np
import time
import csv
import os
from sklearn import metrics
from sklearn.cluster import DBSCAN
import tracemalloc
def ABNF(token):
    specific_tokens = {
        0x0d: "CR",
        0x0a: "LF",  
        0x09: "HTAB",
        0x20: "SP",
        0x22: "DQUOTE",
    }

    res = {"OCTET"}  

    if token in specific_tokens:
        res.add(specific_tokens[token])

    if 0x41 <= token <= 0x5a or 0x61 <= token <= 0x7a:
        res.add("ALPHA")
    if 0x01 <= token <= 0x7f:
        res.add("CHAR")
    if 0x00 <= token <= 0x1f:
        res.add("CTL")
    if 0x30 <= token <= 0x39:
        res.add("DIGIT")
    if 0x30 <= token <= 0x39 or 0x41 <= token <= 0x46:
        res.add("HEXDIG")
    if 0x21 <= token <= 0x7e:
        res.add("VCHAR")

    return res

def jaccard_distance(set_a, set_b):
    intersection = set_a.intersection(set_b)
    union = set_a.union(set_b)
    
    if not union:  
        return 0.0
    
    return 1.0 - (len(intersection) / len(union))

def TFD(a, b):
    a_ABNF = ABNF(a)
    b_ABNF = ABNF(b)
    
    distance = jaccard_distance(a_ABNF, b_ABNF)
    return distance    
    
def levenshtein_distance(list1, list2):
    size_x = len(list1) + 1
    size_y = len(list2) + 1
    matrix = [[0 for _ in range(size_y)] for _ in range(size_x)]
    
    for x in range(size_x):
        matrix[x][0] = x
    for y in range(size_y):
        matrix[0][y] = y
    
    for x in range(1, size_x):
        for y in range(1, size_y):
            if list1[x-1] == list2[y-1]:
                matrix[x][y] = min(
                    matrix[x-1][y] + 1,     # Deletion
                    matrix[x][y-1] + 1,     # Insertion
                    matrix[x-1][y-1]        # No operation
                )
            else:
                matrix[x][y] = min(
                    matrix[x-1][y] + 1,     # Deletion
                    matrix[x][y-1] + 1,     # Insertion
                    matrix[x-1][y-1] + TFD(list1[x-1], list2[y-1])    # Substitution
                )
    
    return matrix[size_x - 1][size_y - 1]

def generate_distance_matrix(A):
    n = len(A)
    dist_matrix = np.zeros((n, n))
    for i in range(n):
        if i%100 == 0:
            print(i)
        for j in range(i, n):
            dist = levenshtein_distance(A[i], A[j])
            dist_matrix[i, j] = dist_matrix[j, i] = dist
    return dist_matrix


def dbscan_clustering_from_distance_matrix(distance_matrix, eps=2.2, min_samples=3):
    if not isinstance(distance_matrix, np.ndarray):
        distance_matrix = np.array(distance_matrix)
    
    if not np.allclose(distance_matrix, distance_matrix.T) or not np.allclose(np.diag(distance_matrix), 0):
        raise ValueError("The distance matrix must be symmetric, and the diagonal elements should be 0")
    
    db = DBSCAN(eps=eps, min_samples=min_samples, metric='precomputed')
    labels = db.fit_predict(distance_matrix)
    
    return labels
def read_data(filename):
    hex_lists = []
    labels = []
    head_data = []
    
    with open(filename, mode='r', newline='') as file:
        reader = csv.reader(file)
        next(reader)
        
        for row in reader:
            if len(row) < 2: 
                continue
            
            hex_string, label = row[:2]
            hex_list = list(bytes.fromhex(hex_string))
            hex_lists.append(hex_list)
            labels.append(label)
            

    hex_lists = hex_lists[:1000]
    offset = 20  
    print("offset:", offset)
    head_data = [hex_list[:offset] for hex_list in hex_lists]    
    return hex_lists, head_data, offset, labels

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
def evaluate_clustering(true_labels, predicted_labels, beta=0.4):
    noise_label = -1
    non_noise_mask = [label != noise_label for label in predicted_labels]
    
    filtered_true_labels = [true_labels[i] for i, mask in enumerate(non_noise_mask) if mask]
    filtered_predicted_labels = [predicted_labels[i] for i, mask in enumerate(non_noise_mask) if mask]

    # Homogeneity, Completeness and V-Measure
    h, c, v = metrics.homogeneity_completeness_v_measure(filtered_true_labels, filtered_predicted_labels, beta=beta)
    
    print(f"Homogeneity: {h:.4f}")
    print(f"Completeness: {c:.4f}")
    print(f"V-Measure: {v:.4f}")    
    return h, c, v

from collections import defaultdict
def output_labels(labels, raw_data, true_labels):
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
    print(f'hdbscan 聚类数量: {n_clusters_}')
    clusters = defaultdict(list)
    for index, label in enumerate(labels):
        clusters[label].append(index)
    
    noise_indices = clusters.pop(-1, []) 
    sorted_clusters = sorted(clusters.items())
    
    num_clusters = len(clusters)
    print(f"Number of clusters: {num_clusters}")
    
    for cluster_label, indices in sorted_clusters:
        #print(f"Cluster {cluster_label}: {', '.join(str(raw_data[i][12]) for i in indices)}")
        print(f"Cluster {cluster_label}: {', '.join(str(true_labels[i]) for i in indices)}")
        #print(f"Cluster {cluster_label}: {', '.join(str(i) for i in indices)}")

    if noise_indices:
        #print(f"Noise points: {', '.join(str(raw_data[i][12]) for i in noise_indices)}")
        print(f"Noise points: {', '.join(str(true_labels[i]) for i in noise_indices)}")
        #print(f"Noise points: {', '.join(str(i) for i in noise_indices)}")
    else:
        print("No noise points found.")
if __name__ =="__main__": 
    tracemalloc.start() 
    dir_name = "cluster_data\\"
    
    filename = "s7comm_1000_new"
    file_path = dir_name + filename +".csv" 
    raw_data, head_data, offset, true_labels = read_data(file_path)

    start_time = time.time()
    distance_matrix = generate_distance_matrix(head_data)
    labels = dbscan_clustering_from_distance_matrix(distance_matrix)
    stop_time = time.time()

    print("time:",stop_time - start_time)
    output_labels(labels, raw_data, true_labels)
    current, peak = tracemalloc.get_traced_memory()

    print(f"Current memory usage: {current / 1024 ** 2:.2f} MB")  
    print(f"Peak memory usage: {peak / 1024 ** 2:.2f} MB")
    h, c, v = evaluate_clustering(true_labels, labels)
    






