import tracemalloc
import numpy as np
import time
#from hdbscan import HDBSCAN
from collections import defaultdict
from sklearn import metrics
import hdbscan
from find_header3 import find_header_boundaries
import matplotlib.pyplot as plt
import os
from clustering_al import*
#from finch import FINCH
#import shutil
from collections import Counter
#####################################################################
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
                    matrix[x-1][y-1] + 1    # Substitution
                )
    
    return matrix[size_x - 1][size_y - 1]

def hex_string_to_list(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


def generate_distance_matrix(A):
    n = len(A)
    dist_matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(i, n):
            dist = levenshtein_distance(A[i], A[j])
            dist_matrix[i, j] = dist_matrix[j, i] = dist
    return dist_matrix

#########################################################################
def output_labels(labels, raw_data, true_labels):
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)

    clusters = defaultdict(list)
    for index, label in enumerate(labels):
        clusters[label].append(index)
    noise_indices = clusters.pop(-1, [])  
    sorted_clusters = sorted(clusters.items())

    label_mapping = {old_label: new_label for new_label, (old_label, _) in enumerate(sorted_clusters)}

    print(f"Number of clusters: {len(sorted_clusters)}")
    print(f"Number of noise points: {len(noise_indices)}")

    for old_label, indices in sorted_clusters:
        new_label = label_mapping[old_label]
        print(f"Cluster {new_label}: {', '.join(str(true_labels[i]) for i in indices)}")

    if noise_indices:
        print(f"Noise points: {', '.join(str(true_labels[i]) for i in noise_indices)}")
    else:
        print("No noise points found.")
##############################################################################
from sklearn.neighbors import NearestNeighbors

def kmeans_plusplus_initialization(samples, num_core_samples, distance_function):
    core_samples = [samples[np.random.choice(len(samples))]]
    
    if len(samples) <= num_core_samples:
        return samples[:num_core_samples]  
    
    distances = np.array([distance_function(sample, core_samples[0]) for sample in samples])
    probabilities = distances ** 2 / np.sum(distances ** 2)

    while len(core_samples) < num_core_samples:
        next_core_index = np.random.choice(len(samples), p=probabilities)
        core_samples.append(samples[next_core_index])

        new_distances = np.array([distance_function(samples[i], core_samples[-1]) for i in range(len(samples))])
        distances = np.minimum(distances, new_distances)
        
        if np.all(distances == 0):
            break
        
        probabilities = distances ** 2 / np.sum(distances ** 2)

    return core_samples



def select_core_samples(samples, num_core_samples, distance_function):
    core_samples = kmeans_plusplus_initialization(samples, 50, distance_function)

    if len(core_samples) < num_core_samples:
        remaining_samples = [x for x in samples if x not in core_samples]
        if len(remaining_samples) == 0:
            remaining_samples = samples
        if len(remaining_samples) < num_core_samples-len(core_samples):
            random_core_indices = np.random.choice(len(remaining_samples), size=num_core_samples-len(core_samples), replace = True)
        else:
            random_core_indices = np.random.choice(len(remaining_samples), size=num_core_samples-len(core_samples), replace = False)
        
        core_samples.extend([remaining_samples[i] for i in random_core_indices] )
    
    return core_samples#np.array([list(x) for x in core_samples])

def reassign_noise_labels(core_labels):

    max_label = np.max(core_labels)+1
    for i,label in enumerate(core_labels):
        if label == -1:
            core_labels[i] = max_label
            max_label += 1
    return core_labels  

def filter_noise_core_samples(core_samples, core_labels):
    non_noise_indices = np.where(core_labels != -1)[0]
    
    filtered_core_samples = core_samples[non_noise_indices]
    filtered_core_labels = core_labels[non_noise_indices]
    
    return filtered_core_samples, filtered_core_labels


def assign_remaining_samples(samples, core_samples, core_labels, distance_function):
    core_labels= reassign_noise_labels(core_labels)
    
    #core_samples, core_labels = filter_noise_core_samples(core_samples, core_labels)
    all_labels = []
    for sample in samples:
        distances = [distance_function(sample, core_sample) for core_sample in core_samples]
        closest_core_index = np.argmin(distances)
        all_labels.append(core_labels[closest_core_index])
    
    return np.array(all_labels)




def cluster_core_samples(dist_matrix, core_samples, algorithm='mix'):
    if algorithm.lower() == 'hdbscan':
        clustering = hdbscan.HDBSCAN(metric='precomputed', min_cluster_size=2, min_samples=2, alpha=0.1)
                                    
        clustering.fit(dist_matrix)  
    elif algorithm.lower() == 'finch':
        c, num, _ = FINCH(dist_matrix, is_distance_matrix=True)
        final_labels = c[:, 1]
        return final_labels 
    elif algorithm.lower() == 'dbscan':
        min_samples, eps_suggestion = autoconfigureDBSCAN(dist_matrix) #k_distance_graph(distance_matrix, min_samples = 2)
        print("dbscan param:",min_samples, eps_suggestion )
        dbscan_labels = dbscan_cluster_matrix(dist_matrix, eps_suggestion, 2)
        return dbscan_labels
    elif algorithm.lower() == 'mix':
        mix_matrix = mix_cluster(dist_matrix, len(core_samples), core_samples)
        best_threshold, best_silhouette_score = find_best_threshold(mix_matrix, dist_matrix, mix_matrix[0,0])
        byte_index = 1  
        final_labels = output_clustering_results(mix_matrix, best_threshold, core_samples, byte_index)
        return final_labels

    else:
        raise ValueError("Unsupported clustering algorithm")
    
    return clustering.labels_

from sklearn.manifold import MDS
def plot_sample(core_dist_matrix):
    mds = MDS(n_components=2, dissimilarity='precomputed', random_state=42)
    samples_2d = mds.fit_transform(core_dist_matrix)
    plt.scatter(samples_2d[:, 0], samples_2d[:, 1], s=50, alpha=0.8)
    plt.title('2D Visualization of Samples using MDS')
    plt.xlabel('Component 1')
    plt.ylabel('Component 2')
    plt.show()   


def hybrid_clustering(samples, num_core_samples, distance_function, raw_data, algorithm='mix'):
    core_samples = select_core_samples(samples, num_core_samples, distance_function)
    core_dist_matrix = generate_distance_matrix(core_samples)

    core_labels = cluster_core_samples(core_dist_matrix, core_samples, algorithm)
    all_labels = assign_remaining_samples(samples, np.array(core_samples), core_labels, distance_function)
    return all_labels


############################################################


############################################################
import csv

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

    
    offset = find_header_boundaries(hex_lists) 
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
############################################################             


def evaluate_clustering(true_labels, predicted_labels, beta=0.4):
    noise_label = -1
    non_noise_mask = [label != noise_label for label in predicted_labels]
    noise_count = len(predicted_labels) - sum(non_noise_mask)
    print(f"Noise labels num: {noise_count}")
    
    filtered_true_labels = [true_labels[i] for i, mask in enumerate(non_noise_mask) if mask]
    filtered_predicted_labels = [predicted_labels[i] for i, mask in enumerate(non_noise_mask) if mask]

    # Homogeneity, Completeness and V-Measure
    h, c, v = metrics.homogeneity_completeness_v_measure(filtered_true_labels, filtered_predicted_labels, beta=beta)
    ari = metrics.adjusted_rand_score(filtered_true_labels, filtered_predicted_labels)
    print(f"Homogeneity: {h:.4f}")
    print(f"Completeness: {c:.4f}")
    print(f"V-Measure: {v:.4f}")  
    print(f"Adjusted Rand Index (ARI): {ari:.4f}")
    return h, c, v

def refine_clusters(labels):
    label_counts = Counter(labels)
    singleton_labels = {label for label, count in label_counts.items() if count == 1 and label != -1}
    refined_labels = [label if label not in singleton_labels else -1 for label in labels]
    
    return np.array(refined_labels)

############################################################
if __name__ =="__main__": 
    # tracemalloc.start() 
    dir_name = "cluster_data\\"
    filename = "smb_1000"

    file_path = dir_name + filename +".csv" 
    
    start_time = time.time()
    raw_data, head_data, offset, true_labels = read_data(file_path)
    #A, original_indices = remove_duplicates(head_data)
    unique_head_data = []
    unique_labels = []
    seen = set()
    
    for i, head in enumerate(head_data):
        head_tuple = tuple(head)
        if head_tuple not in seen:
            seen.add(head_tuple)
            unique_head_data.append(head)
            unique_labels.append(true_labels[i])   
    A = unique_head_data
    print(len(A))
    core_num = 400
    print(filename, core_num)
    
    labels = hybrid_clustering(A, core_num, levenshtein_distance, raw_data, algorithm="mix")
    labels = refine_clusters(labels)
    # current, peak = tracemalloc.get_traced_memory()
    # print(f"Current memory usage: {current / 1024 ** 2:.2f} MB")  # 转换为 MB
    # print(f"Peak memory usage: {peak / 1024 ** 2:.2f} MB")
    end_time = time.time()
    print("time:",end_time - start_time)
    h, c, v = evaluate_clustering(unique_labels, labels)
















