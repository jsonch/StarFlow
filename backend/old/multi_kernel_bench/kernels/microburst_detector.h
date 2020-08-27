
#ifndef STARFLOW_KERNELS_MICROBURST_DETECTOR
#define STARFLOW_KERNELS_MICROBURST_DETECTOR

#include <iostream>
#include <chrono>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>

using namespace std;
using namespace std::chrono;


// Identifies the hosts responsible for microbursts.

#define BENCHMARK_CT_MICROBURST 10000

#ifndef UINT32_MAX
#define UINT32_MAX  (0xffffffff)
#endif

namespace starflow {
	namespace kernels {

		// Data structure to cache flows until they can no longer have packets in the queue. 
		typedef std::pair<string, CLFR_Value> CLFR_PAIR_TYPE;
		struct CLFR_Pair_comp {
			bool operator() (const CLFR_PAIR_TYPE lhs, const CLFR_PAIR_TYPE rhs) const
			{return lhs.second.packetVector.back().ts < rhs.second.packetVector.back().ts;}
		};

		typedef std::pair<uint32_t, PacketFeatures> PKT_PAIR_TYPE;
		// Data structure to reconstruct the queue at the point in time when a drop happened. 
		struct Pkt_Pair_comp {
			bool operator() (const PKT_PAIR_TYPE lhs, const PKT_PAIR_TYPE rhs) const
			{return lhs.second.ts < rhs.second.ts;}
		};

		template<typename T>
		class MicroburstDetector : public raft::kernel
		{
		public:
			std::multiset<CLFR_PAIR_TYPE, CLFR_Pair_comp> orderedCache;
			CLFR_PAIR_TYPE blankClfrPair;
			std::multiset<PKT_PAIR_TYPE, Pkt_Pair_comp> reconstructedQueue;
			PKT_PAIR_TYPE blankPktPair;

			// Which packets of each flow are currently in the reconstructed queue. 
			std::unordered_map<std::string, uint32_t> startPktIdx;

			uint16_t queueThreshold = 20;
			uint16_t lastQueueSize = 0;

			uint64_t counter=0; 

			high_resolution_clock::time_point last, cur; 

			explicit MicroburstDetector()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				input.template add_port<T>("in");
			}

			// enqueue packets that arrived before endtime in all currently active flows. 
			void updateQueue(uint32_t endTime){
				// int oldQueueSize = reconstructedQueue.size();
				for (auto kv : orderedCache){
					startPktIdx.emplace(kv.first, 0);
					// update which packets from this flow are in the queue. 
					for (int idx = startPktIdx[kv.first]; idx<kv.second.packetVector.size(); idx++ ){
						auto p = kv.second.packetVector[idx];
						if (p.ts > endTime){
							startPktIdx[kv.first] = idx; // where to start in next update on this flow. 
							break;
						}

						// place packet into queue reconstructor.
						reconstructedQueue.emplace(*(uint32_t *)(kv.first.c_str()), p);
					}
				}
				// cout << "\tinserted " << reconstructedQueue.size()-oldQueueSize << " packets into queue" << endl;
			}

			// arrive by start time, sort by end time.
			raft::kstatus run() override
			{
				// get a ref to the clfr batch.
				auto &clfrVector(input["in"].template peek<T>());
				counter+= clfrVector.size();

				for (auto kv : clfrVector){
					// Insert into cache. 
					orderedCache.insert(kv);

					// calculate max queue size.
					uint16_t localMaxSize = 0;
					uint32_t localMaxTime = 0;
					uint32_t sizeTally =0;
					uint32_t numAboveThreshold = 0;
					for (auto p : kv.second.packetVector){
						if (p.queueSize > localMaxSize){
							localMaxSize = p.queueSize;
							localMaxTime = p.ts;
						}
						sizeTally+=p.queueSize;
						if (p.queueSize ==24){
							numAboveThreshold++;
						}
					}
					double avgSize = double(sizeTally) / double(kv.second.packetVector.size());
					double pctAboveThreshold = double(numAboveThreshold) / double(kv.second.packetVector.size());
					// do queue processing for important flows. 					
					uint32_t src = *(uint32_t *)(kv.first.c_str());
					if (src > 20){
						cout << "timeseries[" << kv.second.packetVector[0].ts << "]=" << pctAboveThreshold<<endl;
						// cout << kv.second.packetVector[0].ts << " , " << avgSize << " , " << localMaxSize;
					// cout << "flow start time: " << kv.second.packetVector[0].ts << " max queue size: " << localMaxSize << endl;
					// if above threshold, and queue is growing.
						if (localMaxSize >= queueThreshold){
							// cout << "\tqueue threshold (" << queueThreshold << ") reached!" << endl;
							updateQueue(localMaxTime);

							// walk back from end of queue to find out what sources are the cause. 
							std::vector<uint32_t> packetSrcsInQueue;
							for (auto rit = reconstructedQueue.rbegin(); rit!= reconstructedQueue.rend(); ++rit){
								packetSrcsInQueue.push_back((*rit).first);
								if (packetSrcsInQueue.size() >= localMaxSize){
									break;
								}
							}
							std::unordered_set<uint32_t> uniqueOffenders;
							for (auto h : packetSrcsInQueue){
								uniqueOffenders.insert(h);
							}
							// cout << " , " << uniqueOffenders.size();
							// cout << "\tHosts in queue:";
							cout << "occupants["<<kv.second.packetVector[0].ts<<"] = (" <<pctAboveThreshold << ", [ ";
							for (auto h : uniqueOffenders){
								cout << h <<",";
							}
							cout << "] )" << endl;
							// cout << endl;
						}
					}

					lastQueueSize = localMaxSize;


					// Clean up data structures. 

					// remove flows that ended before current flow start time. 
					std::vector<PacketFeatures> nv;
					nv.push_back(kv.second.packetVector[0]);
					blankClfrPair.second.packetVector = nv;
					auto maxOldFlowIt = orderedCache.lower_bound(blankClfrPair);
					orderedCache.erase(orderedCache.begin(), maxOldFlowIt);

					// remove packets from reconstructed queue before current flow start time. 
					blankPktPair.second.ts = kv.second.packetVector[0].ts;
					// (neither could be responsible for high queue sizes that future flows observe).
					auto maxOldPktIt = reconstructedQueue.lower_bound(blankPktPair);
					reconstructedQueue.erase(reconstructedQueue.begin(), maxOldPktIt);

					// cout << "flow cache size: " << orderedCache.size() << " reconstructedQueue size: " << reconstructedQueue.size() << endl;
				}

				input["in"].recycle(); // recycle to move to next item.

				// std::cout << "counter: " << counter << std::endl;
				if (counter > BENCHMARK_CT_MICROBURST){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					// std::cout << std::fixed << "time to process " << BENCHMARK_CT_MICROBURST << " CLFRs: " << duration <<" processing rate: " << 1000.0*(float(counter)/float(duration)) << std::endl;
					counter = 0;
					last = high_resolution_clock::now();
				}

				return (raft::proceed);
			}
		};
	}
}

#endif
