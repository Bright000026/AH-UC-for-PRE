from sklearn.cluster import OPTICS, DBSCAN, Birch
import hdbscan
import numpy as np
import networkx as nx
from sklearn.metrics import silhouette_score
from scipy.spatial.distance import pdist, squareform
from scipy.ndimage import gaussian_filter1d
from math import log, ceil
#from CFSFDP import CFSFDP
#from finch import FINCH

########################################################
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

def generate_distance_matrix(A):
    n = len(A)
    dist_matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(i, n):
            dist = levenshtein_distance(A[i], A[j])
            dist_matrix[i, j] = dist_matrix[j, i] = dist
    return dist_matrix
#######################################################


def generate_neighbors(distance_matrix):
    """
    Generate a list of neighbors for each sample, sorted by distance.

    :param distance_matrix: The pairwise distance matrix.
    :return: List of lists, where each sublist contains tuples of (neighbor_index, distance).
    """
    n = len(distance_matrix)
    neighbors = []
    for idx in range(n):
        dists = distance_matrix[idx]
        # Create a list of (index, distance) pairs excluding the self-distance
        neighbor_list = sorted([(i, d) for i, d in enumerate(dists) if i != idx], key=lambda x: x[1])
        neighbors.append(neighbor_list)
    return neighbors

def autoconfigureDBSCAN(distance_matrix):
    """
    Auto configure the clustering parameters epsilon and minPts regarding the input data.
    this use the method from NEMETYL

    :param distance_matrix: The pairwise distance matrix.
    :return: min_samples, epsilon
    """
    neighbors = generate_neighbors(distance_matrix)
    n = len(neighbors)
    sigma = log(n)
    knearest = {}
    smoothknearest = {}
    seconddiff = {}
    seconddiffMax = (0, 0, 0)

    # Limit k to the first log(n^2) values or the first 10% of k-neighbors, whichever is smaller
    max_k = min(ceil(log(n**2)), int(0.1 * n))

    for k in range(1, max_k + 1):  # Start from 1 to avoid index out of range error
        knearest[k] = [nfori[k-1][1] for nfori in neighbors if len(nfori) > k]  # Ensure we don't go out of bounds
        if not knearest[k]:
            continue  # Skip this k if there are no valid distances

        smoothknearest[k] = gaussian_filter1d(knearest[k], sigma)
        seconddiff[k] = np.diff(smoothknearest[k], 2)

        if len(seconddiff[k]) == 0:
            continue  # Skip if second difference is empty

        seconddiffargmax = seconddiff[k].argmax()
        if seconddiffargmax < len(smoothknearest[k]) - 2 and smoothknearest[k][seconddiffargmax + 1] > 0:
            diffrelmax = seconddiff[k][seconddiffargmax] / smoothknearest[k][seconddiffargmax + 1]
            if 2*sigma < seconddiffargmax < len(smoothknearest[k]) - 2*sigma and diffrelmax > seconddiffMax[2]:
                seconddiffMax = (k, seconddiffargmax, diffrelmax)

    k = seconddiffMax[0]
    x = seconddiffMax[1] + 1  # Adjust index due to np.diff reducing length by 2

    # If epsilon is 0, set it to a very low value to handle evenly distributed samples or noise
    if k in smoothknearest and x < len(smoothknearest[k]):
        epsilon = smoothknearest[k][x] if smoothknearest[k][x] > 0 else 0.001
    else:
        epsilon = 0.001

    min_samples = round(sigma)
    #print("eps {:0.3f} autoconfigured from k {}".format(epsilon, k))
    return min_samples, epsilon

###########################################################
def remove_duplicates(data):
    unique_data = []
    seen = set()
    for item in data:
        item_tuple = tuple(item)  
        if item_tuple not in seen:
            seen.add(item_tuple)
            unique_data.append(item)
    return unique_data

def map_labels_to_original(labels, unique_data, head_data):

    label_dict = {tuple(unique_data[i]): labels[i] for i in range(len(unique_data))}
    

    full_labels = [-1] * len(head_data)
    

    for i, sample in enumerate(head_data):
        sample_tuple = tuple(sample)
        if sample_tuple in label_dict:
            full_labels[i] = label_dict[sample_tuple]
        else:
            raise ValueError(f"Sample {sample} not found in unique data.")
    
    return full_labels
###########################################################


"""
Below is several clustering methods
"""
###########################################################
def dbscan_cluster_matrix(dist_matrix, eps, min_samples):
    
    #min_samples = 2
    db = DBSCAN(eps=eps, min_samples=min_samples, metric='precomputed').fit(dist_matrix)
    #print("=============DBSCAN=================")
    #print(db.labels_)
    return db.labels_

def optics_cluster_matrix(distance_matrix):
    clusterer = OPTICS(metric='precomputed', min_samples=2)
    clusterer.fit(distance_matrix)
    #print("================optics===================")
    #print(clusterer.labels_)
    return clusterer.labels_

def birch_cluster_matrix(feature_matrix, branching_factor=50, n_clusters=None, threshold=5.0):
    clusterer = Birch(branching_factor=branching_factor, n_clusters=n_clusters, threshold=threshold)
    clusterer.fit(feature_matrix)
    return clusterer.labels_

def hdbscan_cluster_matrix(dist_matrix):
    clusterer = hdbscan.HDBSCAN(metric='precomputed', min_cluster_size=2, min_samples=2, alpha=0.1,
                                cluster_selection_epsilon=1)
    clusterer.fit(dist_matrix)
    return clusterer.labels_

def CFSFDP_cluster_matrix(dist_matrix):
    dc = np.percentile(dist_matrix.flatten(), 2)
    rho_threshold = 2
    delta_threshold = 1.0
    
    clusterer = CFSFDP(dc, rho_threshold, delta_threshold)
    clusterer.fit(dist_matrix)
    print("====================CFSFDP====================")
    print(clusterer.labels_)
    return clusterer.labels_

def FINCH_cluster_matrix(dist_matrix):
    c, num, _ = FINCH(dist_matrix, is_distance_matrix=True)
    final_labels = c[:, 0]
    return final_labels 

####################################################

def generate_clusters(co_occurrence_matrix, threshold):
    n_samples = co_occurrence_matrix.shape[0]
    G = nx.Graph()
    
    for i in range(n_samples):
        G.add_node(i)
    
    for i in range(n_samples):
        for j in range(i + 1, n_samples):
            if co_occurrence_matrix[i, j] >= threshold:
                G.add_edge(i, j)
    
    connected_components = list(nx.connected_components(G))
    
    labels = np.full(n_samples, -1, dtype=int)
    for idx, component in enumerate(connected_components):
        if len(component) == 1:
            continue
        for node in component:
            labels[node] = idx
    return labels

def merge_single_sample_clusters(labels):
    unique_labels = sorted(set(label for label in labels if label != -1))
    label_mapping = {old_label: new_label for new_label, old_label in enumerate(unique_labels)}
    label_mapping[-1] = -1
    
    for i in range(len(labels)):
        labels[i] = label_mapping[labels[i]]
    
    return labels

def compute_silhouette_scores(distance_matrix, labels):
    if len(set(labels)) < 2:
        return -1  
    silhouette_avg = silhouette_score(distance_matrix, labels)
    
    return silhouette_avg


def find_best_threshold(co_occurrence_matrix, distance_matrix, max_threshold=6, min_threshold=1,step=1):
    best_threshold = min_threshold
    best_silhouette_score = -1
    
    for threshold in range(min_threshold, max_threshold + 1, step):
        
        labels = generate_clusters(co_occurrence_matrix, threshold)
        labels = merge_single_sample_clusters(labels)
        
        silhouette_score = compute_silhouette_scores(distance_matrix, labels)
        print(f"silhouette_score-{threshold}:",silhouette_score)
        if silhouette_score > best_silhouette_score:
            best_silhouette_score = silhouette_score
            best_threshold = threshold
    
    return best_threshold, best_silhouette_score

def output_clustering_results(co_occurrence_matrix, best_threshold, head_data=0, byte_index=0, single_method=0, output_byte_value=True):
    if single_method == 0:
        labels = generate_clusters(co_occurrence_matrix, best_threshold)
        labels = merge_single_sample_clusters(labels)

    else:
        labels = co_occurrence_matrix
    
    clusters = {}
    if output_byte_value:
        for i, label in enumerate(labels):
            sample = head_data[i]
            byte_value = sample[byte_index]
            if label not in clusters:
                clusters[label] = []
            clusters[label].append((i, byte_value))

    else:
        for i, label in enumerate(labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(i)
            
    return labels             
###################################################
"""
below is the mix for all clustering methods
"""
####################################################
def build_co_occurrence_matrix(labels, n_samples):
    co_occurrence_matrix = np.zeros((n_samples, n_samples), dtype=int)
    for i in range(n_samples):
        for j in range(i, n_samples):
            if i==j:
                co_occurrence_matrix[j, i] += 1
                continue
            elif labels[j] == -1:
                continue
            elif labels[i] == labels[j] and i!=j:
                co_occurrence_matrix[i, j] += 1
                co_occurrence_matrix[j, i] += 1
                
            #elif labels[i] == labels[j] and i==j:
            #    co_occurrence_matrix[j, i] += 1
    return co_occurrence_matrix


def mix_cluster(distance_matrix, n_samples, head_data, matrix = 1):
    
    co_occurrence_matrix = np.zeros((n_samples, n_samples), dtype=int)
    
    #hdbSCAN_labels = hdbscan_cluster_matrix(distance_matrix)
    #CFSFDP_labels = CFSFDP_cluster_matrix(distance_matrix) 
    #finch_labels = FINCH_cluster_matrix(distance_matrix)
    birch_labels = birch_cluster_matrix(distance_matrix)
    optics_labels = optics_cluster_matrix(distance_matrix)
   
    min_samples, eps_suggestion = autoconfigureDBSCAN(distance_matrix) 
    #print("dbscan param:",min_samples, eps_suggestion )
    dbscan_labels = dbscan_cluster_matrix(distance_matrix, eps_suggestion, 2)

    #co_occurrence_matrix += build_co_occurrence_matrix(full_CFSFDP_labels , n_samples)
    #co_occurrence_matrix += build_co_occurrence_matrix(finch_labels, n_samples)
    #co_occurrence_matrix += build_co_occurrence_matrix(hdbSCAN_labels, n_samples)
    co_occurrence_matrix += build_co_occurrence_matrix(dbscan_labels, n_samples)   
    co_occurrence_matrix += build_co_occurrence_matrix(optics_labels, n_samples)
    co_occurrence_matrix += build_co_occurrence_matrix(birch_labels, n_samples)

    return co_occurrence_matrix
    

















