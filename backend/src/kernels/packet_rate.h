// measure rate of a CLFR stream in packets per second

#ifndef STARFLOW_KERNELS_PACKET_RATE
#define STARFLOW_KERNELS_PACKET_RATE

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;

namespace starflow {
	namespace kernels {
		template<typename T>
		class MeasurePacketRate : public raft::kernel
		{
		const int BENCHMARK_CT = 1000000;

		public:
			high_resolution_clock::time_point last, cur; 

			uint64_t flowCounter = 0; 
			uint64_t pktCounter = 0;
			explicit MeasurePacketRate()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
				output.template addPort<double>("stats");
			}

			raft::kstatus run() override
			{
				auto &clfrVector(input["in"].template peek<T>());
				flowCounter+= clfrVector.size();
				for (auto rec : clfrVector){
					pktCounter += rec.second.packetVector.size();
				}
				input["in"].recycle();

				if (pktCounter > BENCHMARK_CT){	
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					output["stats"].push(1000.0*(float(pktCounter)/float(duration)));
					pktCounter = 0;
					last = high_resolution_clock::now();
				}
				return (raft::proceed);
			}
		};
	}
}

#endif
