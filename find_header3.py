import numpy as np
from scipy.signal import argrelextrema
from collections import Counter
import matplotlib.pyplot as plt
import ruptures as rpt

def plot_entropy(entropies, filename):
        
    plt.figure(figsize=(10, 6))
    plt.plot(range(0, len(entropies)), entropies, marker='o')
    plt.title(f'{filename}')
    plt.xlabel('Message Offset')
    if filename == "Average entropies":
        plt.ylabel('Entropy Value')
    else:
        plt.ylabel('Entropy Value')
    plt.grid(True)
    plt.show()
    plt.savefig(f"./Pictures/{filename}.svg", format="svg", dpi=300) 

def calculate_entropy(data):
    if not data:
        return 0
    count = Counter(data)
    probabilities = [float(c) / len(data) for c in count.values()]
    entropy = -sum([p * np.log2(p) for p in probabilities])
    return entropy

def compute_entropies_per_offset(lists):
    max_offset = min(len(lst) for lst in lists)
    print("max_offset:", max_offset)
    entropies = []
    for offset in range(max_offset):
        values_at_offset = [lst[offset] for lst in lists if len(lst) > offset]
        entropies.append(calculate_entropy(values_at_offset))
    return entropies

def compute_entropy_change_rates(entropies):
    #epsilon = np.finfo(float).eps
    entropy_change_rates = np.abs(np.diff(entropies))
    #entropy_change_rates = np.diff(entropies) / (entropies[:-1] + epsilon)
    return entropy_change_rates

def find_local_maxima(arr):
    maxima_indices = []
    for i in range(1, len(arr) - 1):
        if arr[i-1] < arr[i] >= arr[i+1]:
            maxima_indices.append(i)
    return np.array(maxima_indices)

def determine_initial_window_size(entropy_change_rates):
    maxima_indices = argrelextrema(entropy_change_rates, np.greater)[0]+1
    
    if len(maxima_indices) == 1:
        maxima_indices = find_local_maxima(entropy_change_rates)
        
    if len(maxima_indices) == 0 or len(maxima_indices) == 1:
        initial_window_size = int(np.nanmedian(entropy_change_rates)) + 1
    else:
        distances_between_maxima = np.diff(maxima_indices)
        
        initial_window_size = max(distances_between_maxima)
        #initial_window_size = int(np.nanmedian(distances_between_maxima)) + 1
    
    return max(3, initial_window_size)

def compute_entropies_per_offset_with_window(lists, window_size=5):
    avg_entropies = []
    entropies = compute_entropies_per_offset(lists)
    i = 0
    while i <= len(entropies) - 1:
        if i + window_size > len(entropies):
            window_size -= 1
            if window_size < 3: 
                break
            continue
        avg_entropies.append(np.mean(entropies[i:i+window_size]))
        
        i += 1
    return avg_entropies
    
    
    
def compute_entropy_change_rates_for_window(avg_entropies):
    #epsilon = np.finfo(float).eps
    #entropy_change_rates = np.abs(np.diff(avg_entropies) / (avg_entropies[:-1] + epsilon))

    entropy_change_rates = np.diff(avg_entropies)
    return entropy_change_rates


def find_change_points(avg_entropies):
    #algo = rpt.Pelt(model="rbf", min_size = 1).fit(avg_entropies)
    #change_points = algo.predict(n_bkps = 1)

    algo = rpt.KernelCPD(kernel="rbf").fit(avg_entropies)
    change_points = algo.predict(pen = 5)
    print("Changes points:", change_points)

    return change_points

colors = ['red','brown', 'green','purple','blue', 'orange', 'cyan', 'magenta', 'yellow']
def plot_everystep(entropies, entropy_change_rates, avg_entropies, change_points):

    plt.rcParams['xtick.labelsize'] = 15 
    plt.rcParams['ytick.labelsize'] = 15  
    plt.rcParams['legend.fontsize'] = 15  
    
    plt.figure(figsize=(10, 6))  
    plt.plot(range(0, len(entropies)), entropies, marker='o')
    plt.xlabel("Message Offset", fontsize=18)
    plt.ylabel("Entropy Value", fontsize=18)
    plt.grid(True)
    plt.tight_layout()
    save_path_a = "./Pictures/entropies_per_offset.png"
    plt.savefig(save_path_a, format="png", dpi=600, bbox_inches='tight')
    print(f"Figure (a) saved to {save_path_a}")
    plt.close()
    
    plt.figure(figsize=(10, 6))  
    plt.plot(range(0, len(entropy_change_rates)), entropy_change_rates, marker='o')
    plt.xlabel("Message Offset", fontsize=18)
    plt.ylabel("Entropy Change Rate", fontsize=18)
    plt.grid(True)
    plt.tight_layout()
    save_path_b = "./Pictures/entropy_change_rates.png"
    plt.savefig(save_path_b, format="png", dpi=600, bbox_inches='tight')
    print(f"Figure (b) saved to {save_path_b}")
    plt.close()
    
    plt.figure(figsize=(10, 6))  
    plt.plot(range(0, len(avg_entropies)), avg_entropies, marker='o')
    plt.xlabel("Message Offset", fontsize=18)
    plt.ylabel("Avg Entropy Value", fontsize=18)
    plt.grid(True)
    plt.tight_layout()
    save_path_c = "./Pictures/average_entropies.png"
    plt.savefig(save_path_c, format="png", dpi=600, bbox_inches='tight')
    print(f"Figure (c) saved to {save_path_c}")
    plt.close()
    
    plt.figure(figsize=(10, 6))  
    plt.plot(range(0, len(avg_entropies)), avg_entropies, label="Avg Entropy Values", linewidth=2)
    for i, cp in enumerate(change_points):
        plt.axvline(x=cp,color=colors[i % len(colors)], linestyle="--", label=f"Change point {cp}")
    plt.xlabel("Message Offset", fontsize=18)
    plt.ylabel("Avg Entropy Value", fontsize=18)
    plt.grid(True)
    
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))  
    plt.legend(by_label.values(), by_label.keys())
    
    plt.tight_layout()
    save_path_d = "./Pictures/avg_entropy_with_change_points.png"
    plt.savefig(save_path_d, format="png", dpi=600, bbox_inches='tight')
    print(f"Figure (d) saved to {save_path_d}")
    plt.close()


def find_header_boundaries(lists):
    entropies = compute_entropies_per_offset(lists)
    plot_entropy(entropies, "Entropies per offset")

    entropy_change_rates = compute_entropy_change_rates(entropies)
    plot_entropy( entropy_change_rates, " Entropy change rates")

    initial_window_size = determine_initial_window_size(entropy_change_rates)
    print("initial_window_size:", initial_window_size)

    avg_entropies = compute_entropies_per_offset_with_window(lists, window_size=initial_window_size)
    plot_entropy(avg_entropies, "Average entropies")

    header_candidate = find_change_points(np.array(avg_entropies))
    plot_everystep(entropies, entropy_change_rates, avg_entropies, header_candidate)
    return header_candidate[0]
    
def hex_string_to_list(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


if __name__ =="__main__": 
    dirname = "cluster_data/"
    filename = "smb_1000.txt"
    
    hex_lists = []
    with open(dirname+filename, 'r') as file:
        for line in file:
            clean_line = line.strip() 
            hex_lists.append(hex_string_to_list(clean_line))
        while hex_lists and hex_lists[-1] == []:
            hex_lists.pop()

    header_end = find_header_boundaries(hex_lists)
    print(f"{filename} header pos: {header_end}")