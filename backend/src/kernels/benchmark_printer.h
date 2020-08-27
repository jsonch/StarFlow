// Tracks and summarizes throughput stats from multiple ports.
// Prints output in a python friendly format (e.g., to copy and paste into a notebook)
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
			int inC;

			std::unordered_map<int, double> portStats;
			int ctr = 0;
			char * statName;
			explicit BenchmarkPrinter(int inputPortCt, char * stat)
				: raft::kernel()
			{
				statName = stat;
				inC = inputPortCt;
				// Configure the stream processing outputs.
				for (int i=0; i<inC; i++ ){
					portStats[i] = 0.0;
					// cout << " adding input port: " << std::to_string(i) << endl;
					input.template addPort<T>(std::to_string(i));
				}
			cout << "per_input_" << statName << " = []" << endl;
			cout << "aggregate_" << statName << " = []" << endl;
			}

			raft::kstatus run() override
			{
				cout << std::fixed << "per_input_" << statName << "[" << ctr << "]=[";
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
				cout << std::fixed << "aggregate_" << statName << ".append(" << combined << ")" << endl;
				// Update latest stats.
				ctr++;

				return (raft::proceed);
			}
		};
	}
}

#endif
