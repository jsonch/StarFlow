### starflow single kernel backend
*date: 11/2019*

This starflow backend runs a single raftlib kernel that: 

1. Loads microflows from a file.
2. Applies all selected telemetry analysis functions.
3. Reports performance statistics to a downstream kernel.


The goal was to measure raw performance without any overheads from stream processing frameworks or NICs.

Notes: 

The binary in this directory, starflow_app_benchmark, was originally run in 11/2019 on a debian (x86-64) server. 

Currently (8/2020), that server  is offline and inaccessible. So, these source files come from two different versions of the code and may not compile correctly. 

starflow_app_benchmark.cc and kernels/merged_all_metrics.h (the most important files with all the actual analysis code) are from local copies of the 11/2019 benchmark source.

The remaining files come from an older repository.
