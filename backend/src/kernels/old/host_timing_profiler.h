
#ifndef STARFLOW_KERNELS_HOST_PROFILER
#define STARFLOW_KERNELS_HOST_PROFILER

#include <iostream>
#include <fstream>

#include <chrono>
#include <vector>
using namespace std;
using namespace std::chrono;

#include "flat_hash_map.hpp"

// Builds a timing profile of each monitored source address. 
// (example 1)

#define DUMP 1
#define STATS 1
#define BENCHMARK 1
#define BENCHMARK_CT 1000000



namespace starflow {
	namespace kernels {
		template<typename T>
		class HostProfiler : public raft::kernel
		{
		public:
			const char * outFileName;
			uint32_t profileDuration = 0;

			high_resolution_clock::time_point last, cur, start, end; 
			ska::flat_hash_map<uint32_t, std::vector<uint32_t>> hostTimes;
			std::vector<uint32_t> blankValue;		
			uint32_t startTs = 0;
			uint32_t endTs = 0;	


			uint64_t counter=0; 

			// input: profile dump file name, duration of profile (ms).
			explicit HostProfiler(const char *of, uint32_t profDur)
				: raft::kernel()
			{
				outFileName = of;
				profileDuration = profDur;
				last = high_resolution_clock::now();
				start = high_resolution_clock::now();
				input.template add_port<T>("in");
			}

			// Dump profile. Format: host ip, # arrivals, timestamps (all uint_64)
			void dumpProfile(){
				std::cout << "dumping profile to: " << outFileName << std::endl;
				ofstream o;
				o.open(outFileName, ios::binary);
				uint64_t tsesWritten = 0;
				for (auto kv : hostTimes){
					uint32_t hostIp = kv.first;
					uint32_t tsCt = uint32_t(kv.second.size());
					o.write((char *) &hostIp, sizeof(hostIp));
					o.write((char *) &tsCt, sizeof(tsCt));
					for (auto ts : kv.second){
						o.write((char *) &ts, sizeof(ts));
						tsesWritten++;
					}
				}
				o.close();
				std::cout << "\twrote " << tsesWritten << " timestamps" << std::endl;
			}

			raft::kstatus run() override
			{
				// get a referecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());
				// handle a batch. 
				for (auto kv : clfrVector){
					// key is src addr.
					uint32_t key = *((uint32_t *) &(kv.first.c_str()[4]));

					auto got = hostTimes.find(key);
					if (got == hostTimes.end()){
						hostTimes[key] = blankValue;
						got = hostTimes.find(key);
					}
					// update profile.
					for (auto pfs : kv.second.packetVector){
						got->second.push_back(pfs.ts);
						#ifdef STATS
							endTs = max(pfs.ts, endTs);
						#endif
					}
				}

				// handleBatch(clfrVector);

				input["in"].recycle(); // recycle to move to next item.

				// for benchmarking. 
				#ifdef BENCHMARK
				counter+= clfrVector.size();

				if (counter > BENCHMARK_CT){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					std::cout << std::fixed << "time to gen host profiles with " << BENCHMARK_CT << " CLFRs: " << duration <<" processing rate: " << 1000.0*(float(counter)/float(duration)) << std::endl;
					counter = 0;
					last = high_resolution_clock::now();

					#ifdef STATS
					std::cout << "number of hosts: " << hostTimes.size() << " time interval represented: " << (endTs - startTs)/1000.0 << " (ms)" <<  std::endl;
					#endif

				}
				#endif

				#ifdef DUMP
				// Dump profile and exit (entire app for now).
				if ((endTs - startTs) > (profileDuration*1000)){
					end = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( end - start ).count();
					std::cout << "total time to get profile: " << duration << " ms" << std::endl;
					dumpProfile();
					// return (raft::stop);
					exit(0);

				}
				#endif

				return (raft::proceed);
			}

			// void handleBatch(std::vector<T> batchVector){

			// }


		};
	}
}

#endif
