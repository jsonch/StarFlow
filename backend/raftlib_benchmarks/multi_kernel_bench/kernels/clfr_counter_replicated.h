
#ifndef STARFLOW_KERNELS_CLFR_COUNTER_REPLICATED
#define STARFLOW_KERNELS_CLFR_COUNTER_REPLICATED

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;



namespace starflow {
	namespace kernels {
		template<typename T>
		class ClfrCounterReplicated : public raft::kernel
		{
		// Counts CLFRs, gives periodic statistic updates. 
		#define BENCHMARK_CT 1000000


		public:
			int replicaId;
			high_resolution_clock::time_point last, cur; 

			uint64_t counter=0; 
			uint64_t total = 0;
			explicit ClfrCounterReplicated(int rid)
				: raft::kernel()
			{
				replicaId = rid;
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
				output.template add_port<double>("stats");
			}

			raft::kstatus run() override
			{
			if ((total == 0) && (counter == 0))				
				last = high_resolution_clock::now();

				// some black magic to get a refrecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());
				counter+= clfrVector.size();
				// std::cout << clfr.timeStamps[0] << endl;

				// input["in"].unpeek(); // unpeek if it remains in the stream. 
				input["in"].recycle(); // recycle to move to next item.

				// std::cout << "counter: " << counter << std::endl;
				if (counter > BENCHMARK_CT){	
					total += counter;
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					// std::cout << "replica id: " << replicaId << std::fixed << " time to get " << total << " CLFRs: " << duration <<" processing rate: " << 1000.0*(float(total)/float(duration)) << std::endl;
					counter =0;
					// Push latest throughput value to stat tracker.
					output["stats"].push(1000.0*(float(total)/float(duration)));
				}

				return (raft::proceed);
			}
		};
	}
}

#endif
