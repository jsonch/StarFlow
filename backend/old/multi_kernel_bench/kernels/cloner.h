
#ifndef STARFLOW_KERNELS_CLFR_CLONER
#define STARFLOW_KERNELS_CLFR_CLONER

#include <string>
#include <raft>
#include <raftio>

#include <iostream>
#include <chrono>
using namespace std;
using namespace std::chrono;




namespace starflow {
	namespace kernels {
		template<typename T>
		class ClfrCloner : public raft::kernel
		{
		public:
			// Counts CLFRs, gives periodic statistic updates. 
			#define BENCHMARK_CT 1000000
			high_resolution_clock::time_point last, cur; 

			int outC;

			uint64_t counter=0; 
			explicit ClfrCloner(int outputPortCt)
				: raft::kernel()
			{
				outC = outputPortCt;
				last = high_resolution_clock::now();
				input.template addPort<T>("in");
				// Configure the stream processing outputs.
				for (int i=0; i<outputPortCt; i++ ){
					cout << " adding port: " << std::to_string(i) << endl;
					output.template addPort<T>(std::to_string(i));
				}
			}

			raft::kstatus run() override
			{

				// some black magic to get a refrecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());
				counter+= clfrVector.size();
				// std::cout << clfr.timeStamps[0] << endl;

				for (int i = 0; i<outC; i++){
					// auto &out( output[std::to_string(i)].template allocate<T>() );
					auto out( output[std::to_string(i)].template allocate_s<T>() );
					(*out) = clfrVector;
					// output[std::to_string(i)].send();					
				}

				// input["in"].unpeek(); // unpeek if it remains in the stream. 
				input["in"].recycle(); // recycle to move to next item.

				// std::cout << "counter: " << counter << std::endl;
				if (counter > BENCHMARK_CT){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					std::cout << std::fixed << "# outputs: " << outC << " time to clone: " << BENCHMARK_CT << " clfrs: " << duration <<" processing rate: " << 1000.0*(float(counter)/float(duration)) << std::endl;
					counter = 0;
					last = high_resolution_clock::now();
				}

				return (raft::proceed);
			}
		};
	}
}

#endif
