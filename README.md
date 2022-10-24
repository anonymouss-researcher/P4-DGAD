# P4-DGAD

# Description
P4-DGAD is a technique to detect Domain Generation Algorithms (DGAs) in the P4-programmable data plane. The proposed approach collects network and linguistic features of DGA samples. Essentially, the network features are collected prior to the initiation of the first domain that results in NXD response. Once the first NXD response is received, the P4-programmable switch extracts statistical (bigram frequency) and structural features (length of the domain, number of labels, etc.) of the domain name, and sends them, along with the aggregated network features, to the control plane. The control plane measures the randomness level of the domain name and outputs the probability that the domain name is malicious Algorithmically Generated Domain (AGD). Furthermore, this probablitiy is fed as a feature, along side the aggregated network features, to a ML classifier to decide if the host is a DGA or not.


# Dataset
For this work, we use two datasets: 
  1- Pcap of DGAs executed in a contained environment. Each malware sample outputs at least one NXD, and the NXD domain name is checked with DGArchive to be mAGD. 
  
  2- For representing network behavior of normal users, we use CTU-13 dataset (https://www.stratosphereips.org/datasets-ctu13) and we filter the IPs corresponding to the botnets. Thus, the final dataset includes traffic behavior of normal users within the campus. 
  

# Codes
  1- P4 code/P4-DGA.p4: The P4 program that parses the whole domain name of NXDs, extracts the network features, as well as the statistical and structural features of the domain name. The program also includes sending these features to the control plane via message digests.
  2- P4-DGA Python/P4-DGAD-CP.py: the control plane corresponding to the P4 program.
