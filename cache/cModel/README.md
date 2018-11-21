#### starFlow cache C model ####

This is a C model of the starFlow cache that operates on packet traces. It was used in the paper to evaluate cache performance under a range of configurations, some of which are not possible on current tofino hardware. Also, it was used in tuning scripts, to select the best partitioning of the cache. 

The model allows you to configure: 
1. the LRU associativity parameter of the cache *(An associativity parameter of N means that each bucket of the hash table stores up to N entries. When an evict needs to occur to make room for a new entry, the program finds the N entries with the same hash as the new entry, and evicts the least recently used one. To model the Tofino, use an associativity parameter of 1 (no associativity).)*
2. the height of each partition of the cache, i.e., the number of flows slots.
3. the width of each cache partition, i.e., the number of packet features that each flow slot stores.

Usage: 

make starflowModel
./starflowModel PCAP_FILE MAX_TRIAL_DURATION ASSOCIATIVITY_PARAM PARTITION_1_HEIGHT PARTITION_1_WIDTH PARTITION_2_HEIGHT PARTITION_2_WIDTH 

- run example.sh to run the model on the example pcap. 

Notes: 

- edit dumpMClfrs to enable saving grouped packet vectors to binary files. 
- the code structure is a bit unintuitive because it is designed to model the code structure in P4.
- there is a lot of vestigial code that needs to be cleaned up.
