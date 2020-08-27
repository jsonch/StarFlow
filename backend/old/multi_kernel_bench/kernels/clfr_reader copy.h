
#ifndef STARFLOW_KERNELS_CLFR_READER
#define STARFLOW_KERNELS_CLFR_READER

#include "starFlow.h"
#include <iostream>
#include <fstream>
#include <vector>

#include <chrono>
using namespace std;
using namespace std::chrono;


#include "flat_hash_map.hpp"

#define BATCH_SIZE_READER 100

namespace starflow {
	namespace kernels {
		class ClfrReader : public raft::kernel
		{
		public:

			char * inBuf; // Buffer for CLFRs to replay. 
			char * bufPos;
			char * bufEnd;

			// output type: what the kernel emits. 
			// A batch of CLFRs.
			using output_t = std::vector<std::pair<std::string, CLFR_Value>>;

			// ptr to a reference.
			std::vector<std::pair<std::string, CLFR_Value>> * batchVec = NULL;
			
			// for profiling.
			high_resolution_clock::time_point last, cur; 

			// Load the eval data set into RAM. This would be done by the NIC. 
			void loadClfrs(const char *inFile){
				FILE *f = fopen(inFile, "rb");
				fseek(f, 0, SEEK_END);
				long f_sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				std::cout << "loading " << f_sz << " bytes of CLFRs." << std::endl;
				inBuf = (char *) malloc(f_sz);
				std::cout << "finished mallocing" << std::endl;
				fread((char *)inBuf, f_sz, 1, f);
				fclose(f);
				std::cout << "finished reading" << std::endl;
				bufPos = inBuf;
				bufEnd = inBuf + f_sz;
			}

			ClfrReader(const std::string& fn) : raft::kernel()
			{
				last = high_resolution_clock::now();

				// Load microflows in. 
				loadClfrs(fn.c_str());

				// Configure the stream processing outputs.
				output.template add_port<output_t>("out");
			}

			void sendBatch(){
				// Send the output vector. 
				output["out"].send();
				// Get new batch vec.
				auto &out( output["out"].template allocate<output_t>() );
				batchVec = &out;
				batchVec->reserve(BATCH_SIZE_READER);
			}

			raft::kstatus run() override
			{
				if (batchVec == NULL){
					// Get new batch vec.
					auto &out( output["out"].template allocate<output_t>() );
					batchVec = &out;
					batchVec->reserve(BATCH_SIZE_READER);
				}

				uint64_t ctr = 0;
				// Parse CLFRs, fill, send.
				while (bufPos<bufEnd){
					std::string keyStr;
					CLFR_Value val;

					// Key.
					keyStr = std::string((char*)bufPos, 13);
					bufPos+=13;
					// Flow features.
					val.flowFeatures = *(FlowFeatures*)bufPos;
					bufPos+=sizeof(FlowFeatures);
					// Packet features.
					for (int i=0; i<val.flowFeatures.pktCt; i++){
						val.packetVector.push_back(*(PacketFeatures*)bufPos);
						bufPos+= sizeof(PacketFeatures);
					}
					// Append to batch.
					batchVec->emplace_back(keyStr, val);
					// Send.
					if (batchVec->size() > BATCH_SIZE_READER){
						sendBatch();
					}
				}
				// std::cout << "done replaying CLFRs." << std::endl;
				output["out"].send();
				return (raft::stop);
				// exit(0);

				// Return / push.
				return (raft::proceed);
			}
		};
	}
}

#endif
