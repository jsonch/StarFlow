
#ifndef STARFLOW_KERNELS_CLFR_COUNTER
#define STARFLOW_KERNELS_CLFR_COUNTER

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;



namespace starflow {
	namespace kernels {
		template<typename T>
		class ClfrCounter : public raft::kernel
		{
		// Counts CLFRs, gives periodic statistic updates. 
		#define BENCHMARK_CT 1000000


		public:
			high_resolution_clock::time_point last, cur; 

			uint64_t counter=0;
			uint64_t flowCounter = 0; 
			uint64_t pktCounter = 0;
			explicit ClfrCounter()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
			}

			raft::kstatus run() override
			{

				// some black magic to get a refrecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());
				counter+= clfrVector.size();
				flowCounter+= clfrVector.size();
				for (auto rec : clfrVector){
					pktCounter += rec.second.packetVector.size();
				}
				// std::cout << clfr.timeStamps[0] << endl;

				// input["in"].unpeek(); // unpeek if it remains in the stream. 
				input["in"].recycle(); // recycle to move to next item.

				// std::cout << "counter: " << counter << std::endl;
				if (counter > BENCHMARK_CT){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					// cur = high_resolution_clock::now();
					// auto duration = duration_cast<milliseconds>( cur - last ).count();
					// std::cout << std::fixed << "time to get " << BENCHMARK_CT << " CLFRs: " << duration <<" processing rate: " << 1000.0*(float(counter)/float(duration)) << std::endl;
					// std::cout << "packet count: " << pktCounter << " CLFR count: " << flowCounter << endl;
					// counter = 0;
					// last = high_resolution_clock::now();
				}

				return (raft::proceed);
			}
		};
	}
}

#endif
