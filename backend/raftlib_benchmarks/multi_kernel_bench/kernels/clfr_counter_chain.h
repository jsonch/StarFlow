
#ifndef STARFLOW_KERNELS_CLFR_COUNTER_CHAIN
#define STARFLOW_KERNELS_CLFR_COUNTER_CHAIN

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;



namespace starflow {
	namespace kernels {
		template<typename T>
		class ClfrCounterChain : public raft::kernel
		{
		// Counts CLFRs, gives periodic statistic updates. 
		#define BENCHMARK_CT 1000000


		public:
			high_resolution_clock::time_point last, cur; 
			uint64_t counter=0; 
			explicit ClfrCounterChain()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
				output.template add_port<T>("out");
			}

			raft::kstatus run() override
			{

				// some black magic to get a refrecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());
				counter+= clfrVector.size();
				// std::cout << clfr.timeStamps[0] << endl;

				// Send to next counter.
				auto out( output["out"].template allocate_s<T>() );
				(*out) = clfrVector;

				// input["in"].unpeek(); // unpeek if it remains in the stream. 
				input["in"].recycle(); // recycle to move to next item.


				// std::cout << "counter: " << counter << std::endl;
				if (counter > BENCHMARK_CT){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					// if (doPrint){
					// 	std::cout << std::fixed << "time to get " << BENCHMARK_CT << " CLFRs: " << duration <<" processing rate: " << 1000.0*(float(counter)/float(duration)) << std::endl;
					// }
					counter = 0;
					last = high_resolution_clock::now();
				}

				return (raft::proceed);
			}
		};
	}
}

#endif
