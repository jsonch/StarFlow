// Reads microflows from a binary file, converts them to clfrs, and streams them out.
#ifndef STARFLOW_KERNELS_MICROFLOW_READER
#define STARFLOW_KERNELS_MICROFLOW_READER


#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>    // std::max
#include <chrono>

using namespace std;
using namespace std::chrono;


#include "starFlow.h"
#include "flat_hash_map.hpp"

#define BATCH_SIZE 200
#define MF_BATCH_SIZE 500

// #define DUMPCLFRS 1
#define BENCHMARK 1
#define BENCHMARK_CT 1000000

namespace starflow {
	namespace kernels {
		class MicroflowReader : public raft::kernel
		{
		

		public:
			// output type: what the kernel emits. 
			// A batch of CLFRs.
			using output_t = std::vector<std::pair<std::string, CLFR_Value>>;
			// ptr to output batch vector.
			std::vector<std::pair<std::string, CLFR_Value>> * batchVec = NULL;

			char * inBuf, * bufPos, * bufEnd; // Buffer where microflows from PFEs end up. 

			// A map of CLFRs. 
			ska::flat_hash_map<std::string, CLFR_Value> CLFR_flatmap;
			CLFR_Value blankValue;

			// Timeout stuff, in usec.
			uint32_t timeoutCheckPeriod = 5000*1000; // 5 seconds.
			uint32_t timeoutThreshold = 10000*1000; // 10 seconds.
			uint32_t curTs = 0;
			uint32_t lastCheckTs = 0;

			
			// for profiling.
			high_resolution_clock::time_point last, cur; 
			uint64_t mfCt = 0;
			uint64_t totalMfCt = 0;
			uint64_t finCt = 0;
			uint64_t timeoutCt = 0;

			uint64_t tmpCtr = 0;
			uint64_t lastMfCt = 0;

			uint64_t finalMfCt = 0;
			uint64_t finalClfrCt = 0;

			uint64_t total = 0;
			// for dumping CLFRs, if set.
			ofstream o;

			// Load the eval data set into RAM. This would be done by the NIC. 
			void loadMicroflows(const char *inFile){

				FILE *f = fopen(inFile, "rb");
				fseek(f, 0, SEEK_END);
				long f_sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				std::cout << "# loading " << f_sz << " bytes of microflows." << std::endl;
				inBuf = (char *) malloc(f_sz);
				std::cout << "# finished mallocing" << std::endl;
				fread((char *)inBuf, f_sz, 1, f);
				fclose(f);
				std::cout << "# finished reading" << std::endl;
				bufPos = inBuf;
				bufEnd = inBuf + f_sz;
			}

			MicroflowReader(const std::string& fn) : raft::kernel()
			{

				// Load microflows in. 
				loadMicroflows(fn.c_str());
				// Read metadata (# of microflows. )
				ifstream insz;
				insz.open(fn + std::string(".len"), ios::binary);
				insz.read((char*)&totalMfCt, sizeof(totalMfCt));
				insz.close();

				// Configure the stream processing outputs.
				output.template addPort<output_t>("out");
				output.template addPort<double>("stats");

				// initial hash table size
				CLFR_flatmap.reserve(262144);

				blankValue.flowFeatures = {0};
				blankValue.packetVector.reserve(4);
				#ifdef DUMPCLFRS
					std::cout << "dumping CLFRs to: " << fn + std::string(".clfrs") << std::endl;
					o.open(fn + std::string(".clfrs"), ios::binary);
				#endif

				last = high_resolution_clock::now();

			}

			void sendBatch(){
				finalClfrCt+=batchVec->size();
				#ifdef DUMPCLFRS
					for (auto kv : (*batchVec)){
						o.write(kv.first.c_str(), KEYLEN);
						if (kv.second.flowFeatures.pktCt != kv.second.packetVector.size()){
							std::cout << "size error: " << kv.second.flowFeatures.pktCt << " vec len: " << kv.second.packetVector.size() << std::endl;
							exit(1);
						}
						o.write((char *)&(kv.second.flowFeatures), sizeof(kv.second.flowFeatures));
						for (auto pf : kv.second.packetVector){
							o.write((char *)&pf, sizeof(pf));						
						}

					}
				#endif
				// Send the output vector. 
				output["out"].send();
				// Get new batch vec.
				auto &out( output["out"].template allocate<output_t>() );
				batchVec = &out;
				batchVec->reserve(BATCH_SIZE);
			}

			// Check flows for timeouts. 
			// Last update time > 
			void timeoutFlows(){
				uint64_t newTimeouts = 0;
				for (auto kv : CLFR_flatmap){
					if (curTs - kv.second.packetVector.back().ts > timeoutThreshold){
						// std::cout << " timeout: " << kv.second.packetVector.back().ts << " cur: " << curTs << std::endl;
						batchVec->emplace_back(kv.first, kv.second);
						CLFR_flatmap.erase(kv.first);
						timeoutCt++;	
						newTimeouts++;					
						if (batchVec->size() > BATCH_SIZE){
							sendBatch();
						}

					}
				}
				// std :: cout << "new timeouts: " << newTimeouts << std::endl;
				lastCheckTs = curTs;
			}

			// Aggregate MF_BATCH_SIZE microflow, add finished flows to output. 
			void readMicroflows(){

				char * key_chr;
				FlowFeatures * flow_features;
				PacketFeatures *pkt_features;
				// Parse MF_BATCH_SIZE microflows. 
				for (int i=0; i<(MF_BATCH_SIZE-batchVec->size())+1; i++){
					finalMfCt ++;
					// parse key.
					key_chr = bufPos;
					bufPos += KEYLEN;
					// parse flow features.
					flow_features = (FlowFeatures *) bufPos;
					bufPos += sizeof(FlowFeatures);

					// parse packet features.
					pkt_features = (PacketFeatures *) bufPos;
					bufPos+= sizeof(PacketFeatures) * flow_features->pktCt;

					// insert.
					std::string keyStr = std::string(key_chr, 13);

					auto got = CLFR_flatmap.find(keyStr);
					if (got == CLFR_flatmap.end()){
						CLFR_flatmap[keyStr] = blankValue;
						got = CLFR_flatmap.find(keyStr);
					}

					// update flow features. 
					got->second.flowFeatures.pktCt+= flow_features->pktCt;
					// append packet features to vectors. 
					for (int i=0; i<flow_features->pktCt; i++){
						got->second.packetVector.push_back(*pkt_features);
						pkt_features++;		
					}
      				// estimate cur ts, for timeouts.
					curTs = std::max(curTs, got->second.packetVector.back().ts);

					// std::cout << " ----" << std::endl;
					// Evict if fin. 
					if (((flow_features->th_flags & TH_FIN) == TH_FIN) || ((flow_features->th_flags & TH_RST) == TH_RST)) {
						batchVec->emplace_back(keyStr, got->second);
						finCt++;
						CLFR_flatmap.erase(keyStr);
      				}
      								if (batchVec->size() > BATCH_SIZE){
					sendBatch();
				}

				}

				if (batchVec->size() > BATCH_SIZE){
					sendBatch();
				}
				mfCt+= MF_BATCH_SIZE;
			}

			// Read microflows from a per-port file, emit batches of CLFRs.
			raft::kstatus run() override
			{

				if (batchVec == NULL){
					// Get new batch vec.
					auto &out( output["out"].template allocate<output_t>() );
					batchVec = &out;
					batchVec->reserve(BATCH_SIZE);
				}
				// Read microflows and push finished flows to batch vector. 
				readMicroflows();
				lastMfCt += MF_BATCH_SIZE;

				// Check timeouts, if necessary, push to batch vector.
				if (curTs - lastCheckTs > timeoutCheckPeriod){
					timeoutFlows();
				}

				benchmark();
				if ((mfCt+MF_BATCH_SIZE) > totalMfCt){
					// std::cout<<"resetting input buffer." <<std::endl;
					// std::cout<<"input buffer finished. stopping." <<std::endl;
					// std::cout<<"final mf ct: " << finalMfCt << " clfr ct: " << finalClfrCt << std::endl;
					#ifdef DUMPCLFRS
						o.close();
					#endif

					return (raft::stop);
				}

				// Return / push.
				return (raft::proceed);
			}

			void benchmark(){
				#ifdef BENCHMARK
				if (lastMfCt > BENCHMARK_CT ){
					total += lastMfCt;
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					// std::cout << std::fixed << "time to process BENCHMARK_CT MFs: " << duration <<" processing rate: " << 1000.0*(float(lastMfCt)/float(duration)) << std::endl;
					// std::cout << "fin ct: " << finCt << " timeout ct: " << timeoutCt << std::endl;
					// std::cout << "table size: " << CLFR_flatmap.size() << std::endl;
					// Push latest throughput value to stat tracker.
					output["stats"].push(1000.0*(float(total)/float(duration)));

					lastMfCt = 0;

					// last = high_resolution_clock::now();
				}

				#endif
			}


		};
	}
}

#endif
