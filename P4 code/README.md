# Steps to test P4DGAD:
	
1- Compile and run P4DGAD.p4 (P4_16) using Barefoot SDE compiler.
2- Run the control plane CP/P4DGAD_cp.py that receives the data from the data plane (P4DGAD switch) using message digests. The control plane populates the switch with the necessary table entries such as the bigram frequency values and valid TLD. 


