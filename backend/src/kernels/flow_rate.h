// measure rate of a CLFR stream in flows per second

#ifndef STARFLOW_KERNELS_FLOW_RATE
#define STARFLOW_KERNELS_FLOW_RATE

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;

namespace starflow {
	namespace kernels {
		template<typename T>
		class MeasureFlowRate : public raft::kernel
		{
		const int BENCHMARK_CT = 1000000;

		public:
			high_resolution_clock::time_point last, cur; 

			uint64_t flowCounter = 0; 
			explicit MeasureFlowRate()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
				output.template addPort<double>("stats");
			}

			raft::kstatus run() override
			{
				auto &flowRecBatch(input["in"].template peek<T>());
				flowCounter+= flowRecBatch.size();
				input["in"].recycle();

				if (flowCounter > BENCHMARK_CT){	
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					output["stats"].push(1000.0*(float(flowCounter)/float(duration)));
					flowCounter = 0;
					last = high_resolution_clock::now();
				}
				return (raft::proceed);
			}
		};
	}
}

#endif
