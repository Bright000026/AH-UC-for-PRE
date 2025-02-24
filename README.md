# AH-UC-for-PRE

### Code for Adaptive Header Identification and Unsupervised Clustering Strategy for Enhanced Protocol Reverse Engineering

---

### Preprocessing

- **Message Type Preprocessing**: Code is located in `msg_type_data_preprocessing`.
- **Format Preprocessing**: Code is located in `format_label`. We modified the code from FSIBP(https://github.com/5tmFPUPx/FSIBP), such as `test2csv`. Since some public datasets are formatted in `.txt` (e.g., BinaryInferno) instead of `.pcap`, we wrote `test2csv` which could input `.txt` and output `.csv` with format labels.

---

### Clustering and Header Identification

- **Ensemble Clustering**: Code is located in `clustering_al.py`.
- **Adaptive Header Identification**: Code is located in `find_header3.py`.
- **Message Type Identification**: The main code is located in `kmeans++_header_clustering.py`.
- **Memory and Time Test**: Code is located in `mem_time_test.py` for testing the memory and time usage of our method.

---

### Re-implementation of MFD&DBSCAN

- **Evaluation**: Code is located in `eval_MFD_DBSCAN.py`. This is a re-implementation of the method described in the paper:  
  *Fanghui Sun, Shen Wang, Chunrui Zhang, and Hongli Zhang. Clustering of unknown protocol messages based on format comparison. Computer Networks, 179:107296, 2020.*

---

### NEMETYL Test

- **Code Location**: Test for NEMETYL is in the `nemesys` folder, which is the source code from [https://github.com/vs-uulm/nemesys](https://github.com/vs-uulm/nemesys).  
  To make it compatible with our data (`.csv`), we modified `nemesys/src/nemetyl.py`, which is the main source file for NEMETYL.  
  **How to run**:  
  ```bash
  ./src/nemetyl.py ./input/csv/smb2_1000.csv -e -f nemetyl -t nemesys
`-e` is used for little endian, and `-t` specifies the format inference method. For more details, refer to [vs-uulm/nemesys](https://github.com/vs-uulm/nemesys).

### NETZOB Testing

- Located in `netzob_evl.py`, primarily utilizing `ClusterByAlignment` provided by Netzob.

### Format Inference Code

- **Location**: `original\binaryinferno`
- **Details**: Modifications were mainly made to the blackboard for implementing hierarchical inference. Additionally, improvements were made to the pattern detector in binaryinferno to address errors encountered in complex situations. The function code source is located in `set_seq_infer.py`.

**Note**: The paper is currently under review. Once accepted, detail data will be uploaded.
  
