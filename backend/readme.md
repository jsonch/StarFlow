## StarFlow raftlib-based backend

This directory contains raftlib kernels that implement key parts of the starflow backend, and a simple exapmle program that benchmarks single instances of kernel pipelines. 

### Dependencies

* libraft [[1]](https://github.com/RaftLib/RaftLib)

### Input datasets

You can download input datasets (about 2.5GB) to use with the benchmarking program here: 

https://drive.google.com/drive/folders/1cZmwCv0IhNUmUSo18VtCDUSsPGD3JLAi?usp=sharing

Put the files in ./inputs (filenames are hard-coded in the benchmarking program).

- ``mCLFRs.32.bin`` -- a short micro-CLFR trace from a CAIDA dataset. 

- ``microburst.clfrs.bin`` -- a synthetic trace with microbursts, for benchmarking the microburst detector.

### Usage

make
./benchmark_main

*See example.out for output from an example run.*

### Important files

- ``benchmark_main.cpp`` -- this benchmarks single instances of the following raftlib pipelines, on in-memory datasets: 
	- micro-CLFR to CLFR conversion.
	- CLFR reading from memory.
	- CLFR processing (flow metric calculation and microburst detection)

- ``kernels/microflow_reader.h`` -- transforms micro-CLFRs (i.e., the format of telemetry data exported by a switch) into full CLFRs. For benchmarking, this kernel pre-loads mCLFRs from a file to a buffer. In production, it would read from a socket or a ringbuffer populated by a NIC.

- ``kernels/feature_calculator.h``, ``kernels/microburst_detector.h`` -- example CLFR-based apps


### Notes

CLFR stands for "compact lossless flow records". They are a compact and efficient format for storing and analyzing packet-level telemetry data. A CLFR contains a flow key, some flow-level metadata, and a small tuple of features from every packet in the flow. In the starflow paper (ATC 18'), we renamed CLFRs to GPVs ("grouped packet vectors"). 
