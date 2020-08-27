// writes clfrs to a binary file.
#ifndef STARFLOW_KERNELS_CLFR_WRITER
#define STARFLOW_KERNELS_CLFR_WRITER

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

namespace starflow {
    namespace kernels {
        template<typename T>        
        class ClfrWriter : public raft::kernel
        {       
            ofstream o;     
            uint64_t clfrCt = 0;
            uint64_t pktCt = 0;
            uint64_t byteCt = 0;

        public: 
            ClfrWriter(const std::string& fn) : raft::kernel() {
                std::cout << "# writing CLFRs to: " << fn << std::endl;
                o.open(fn, ios::binary);
                input.template add_port<T>("in");
            }
            virtual ~ClfrWriter(){
                std::cout << "# wrote " << clfrCt << " clfrs (" << byteCt << "bytes ) representing " << pktCt << " packets " << endl;
                float bytesPerPkt = byteCt / float(pktCt);
                float pktsPerClfr = float(pktCt) / clfrCt;
                std::cout << "# bytes per packet: " << bytesPerPkt << endl;
                std::cout << "# packets per record: " << pktsPerClfr << endl;
                o.close();
            }
            raft::kstatus run() override {
                auto &clfrBatch(input["in"].template peek<T>());
                for (auto kv : clfrBatch) {
                    clfrCt += 1;
                    pktCt += kv.second.flowFeatures.pktCt;
                    o.write(kv.first.c_str(), KEYLEN);
                    byteCt += KEYLEN;
                    // sanity check.
                    if (kv.second.flowFeatures.pktCt != kv.second.packetVector.size()){
                        std::cout << "size error: " << kv.second.flowFeatures.pktCt << " vec len: " << kv.second.packetVector.size() << std::endl;
                        exit(1);
                    }
                    o.write((char *)&(kv.second.flowFeatures), sizeof(kv.second.flowFeatures));
                    byteCt += sizeof(kv.second.flowFeatures);
                    for (auto pf : kv.second.packetVector){
                        o.write((char *)&pf, sizeof(pf));                       
                        byteCt += sizeof(pf);
                    }
                }
                input["in"].recycle();
            }
        };
    }
}
#endif