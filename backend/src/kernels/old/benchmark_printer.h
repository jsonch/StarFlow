
#ifndef STARFLOW_KERNELS_BENCHMARK_PRINTER
#define STARFLOW_KERNELS_BENCHMARK_PRINTER

#include <string>
#include <raft>
#include <raftio>

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;

#include <unordered_map>

namespace starflow {
	namespace kernels {
		template<typename T>
		class BenchmarkPrinter : public raft::kernel
		{
		public:
			// Tracks and summarizes throughput stats from multiple ports.
			#define BENCHMARK_CT 1000000

			int inC;

			std::unordered_map<int, double> portStats;
			int ctr = 0;
			explicit BenchmarkPrinter(int inputPortCt)
				: raft::kernel()
			{
				inC = inputPortCt;
				// Configure the stream processing outputs.
				for (int i=0; i<inC; i++ ){
					portStats[i] = 0.0;
					// cout << " adding input port: " << std::to_string(i) << endl;
					input.template addPort<T>(std::to_string(i));
				}
			cout << "stats = {}" << endl;
			cout << "combined = []" << endl;
			}

			raft::kstatus run() override
			{

				cout << std::fixed << "stats[" << ctr << "]=[";
				double combined = 0;
				for (int i = 0; i<inC; i++){
					T latestThroughput;
					input[std::to_string(i)].pop(latestThroughput);
					portStats[i] = latestThroughput;
					input[std::to_string(i)].recycle(); // recycle to move to next item.
					cout << latestThroughput << ", ";
					combined += latestThroughput;
				}
				cout << "]" << endl;
				cout << std::fixed << "combined.append(" << combined << ")" << endl;
				// Update latest stats..
				ctr++;

				return (raft::proceed);
			}
		};
	}
}

#endif
