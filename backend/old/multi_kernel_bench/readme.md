###Multi-kernel benchmarks

**Todo: upload build instructions and example input files.**

This directory contains a set of older (late 2017) in-memory benchmarks of a raftlib-based starflow backend. 

####important files:

- ``clfr_converter_main.cc`` -- this benchmarks a raftlib pipeline that reads telemetry records in a switch-exported format (using kernels/microflow_reader.h) and converts them into CLFR records (each CLFR has a flow key and a vector of packet features). 

- ``clfr_driver_main.cc`` -- this benchmarks raftlib pipelines that run one or more kernels that analyze clfrs. 

- ``kernels/microflow_reader.h`` -- transforms micro-CLFRs (i.e., the format of telemetry data exported by a switch) into full CLFRs. For benchmarking, this kernel pre-loads mCLFRs from a file to a buffer. In production, it would read from a socket or a ringbuffer populated by a NIC.

- ``kernels/host_timing_profiler.h``, ``kernels/microburst_detector.h``, ``kernels/*FeatureCalculator.h`` -- various CLFR-based analysis kernels.

- ``kernels/printer.h`` -- a sink for when multiple instances of an analysis kernel run in parallel. It prints performance statistics. 


####notes: 

CLFR stands for "compact lossless flow records". They are a compact and efficient format for storing and analyzing packet-level telemetry data. A CLFR contains a flow key, some flow-level metadata, and a small tuple of features from every packet in the flow. In the starflow paper (ATC 18'), we renamed CLFRs to GPVs ("grouped packet vectors"). 

