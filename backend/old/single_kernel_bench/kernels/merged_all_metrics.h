// Measure increasingly complex subsets of metrics.
#ifndef STARFLOW_SINGLE_BENCHMARK_KERNEL
#define STARFLOW_SINGLE_BENCHMARK_KERNEL

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "starFlow.h"
#include "flat_hash_map.hpp"


#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <numeric>
#include <algorithm>    // std::min_element, std::max_element

#include <chrono>
#include <vector>
using namespace std;
using namespace std::chrono;

#include <dlib/svm_threaded.h>
#include <dlib/rand.h>
using namespace std;
using namespace dlib;

#include <netinet/in.h>
#include <unordered_map>

#include <queue>
#include <set>
#include <unordered_set>


// max number of packet features to use for classification.
#define MINPKT_CT 8

#define QUEUE_WARN_PROB 10

namespace starflow {
	namespace kernels {

		// Data structure for queueMates.
		// Data structure to cache flows until they can no longer have packets in the queue. 
		typedef std::pair<string, CLFR_Value> CLFR_PAIR_TYPE_;
		struct CLFR_Pair_comp_ {
			bool operator() (const CLFR_PAIR_TYPE_ lhs, const CLFR_PAIR_TYPE_ rhs) const
			{return lhs.second.packetVector.back().ts < rhs.second.packetVector.back().ts;}
		};

		typedef std::pair<uint32_t, PacketFeatures> PKT_PAIR_TYPE_;
		// Data structure to reconstruct the queue at the point in time when a drop happened. 
		struct Pkt_Pair_comp_ {
			bool operator() (const PKT_PAIR_TYPE_ lhs, const PKT_PAIR_TYPE_ rhs) const
			{return lhs.second.ts < rhs.second.ts;}
		};


		template<typename T>
		class MetricBackend : public raft::kernel
		{
		public:
			// microflow reader functions.
			high_resolution_clock::time_point startTs, endTs;
			int rid = 0;
			bool started = false;

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

			// End microflow reader setup.


			// Which metrics to measure.
			bool fewMetrics = false;
			bool manyMetrics = false;
			bool appLabel = false;
			bool hostProfile = false;
			bool queueMates = false;

			// state for queue scanner.
			std::multiset<CLFR_PAIR_TYPE_, CLFR_Pair_comp_> orderedCache;
			CLFR_PAIR_TYPE_ blankClfrPair;
			std::multiset<PKT_PAIR_TYPE_, Pkt_Pair_comp_> reconstructedQueue;
			PKT_PAIR_TYPE_ blankPktPair;
			// Which packets of each flow are currently in the reconstructed queue. 
			std::unordered_map<std::string, uint32_t> startPktIdx;

			uint16_t queueThreshold = 20;
			uint16_t lastQueueSize = 0;


			// state for host profiler.
			ska::flat_hash_map<uint32_t, std::vector<uint32_t>> hostTimes;
			std::vector<uint32_t> blankValue_host;		

			// features for classifier.
			typedef matrix<double,12+MINPKT_CT,1> sample_type;
			typedef linear_kernel<sample_type> kernel_type;

			// high_resolution_clock::time_point last, cur; 

			uint64_t counter=0; 

			// Training samples and labels.
			std::vector<sample_type> samples;
			std::vector<double> labels;

			// feature and label of current flow.
			sample_type curFeatures;
			double curLabel;

			// normalizer.
			vector_normalizer<sample_type> normalizer;

			// ML models.
			bool modelBuilt = false;
			svm_multiclass_linear_trainer<kernel_type> svm_trainer;
			// the actual decision rule.
			multiclass_linear_decision_function<kernel_type> df;

			// classes of ports to train on.
			std::unordered_map<uint16_t, double> portClasses { {443, 1.0},
																  {22, 2.0},
																  {1935, 3.0},
																  {53, 4.0},
																  {27015, 5.0},
																};
			std::unordered_map<double, std::string> portNames { {1.0, "https"},
																  {2.0, "ssh"},
																  {3.0, "rtmp"},
																  {4.0, "dns"},
																  {5.0, "cs"},
																};
			std::unordered_map<double, int> sampleCounts{{1.0, 0}, {2.0, 0},{3.0, 0},{4.0, 0},{5.0, 0}};

			std::unordered_map<double, int> correctCounts{{1.0, 0}, {2.0, 0},{3.0, 0},{4.0, 0},{5.0, 0}};
			std::unordered_map<double, int> totalCounts{{1.0, 0}, {2.0, 0},{3.0, 0},{4.0, 0},{5.0, 0}};

			// explicit MetricBackend(int metricSet)
			// 	: raft::kernel()
			// {
			// 	// Load model from df.dat (11/19)
			// 	loadModel();
			// 	input.template add_port<T>("in");
			// 	std::cout << "#metrics:" <<std::endl;
			// 	if (metricSet == 1)
			// 		fewMetrics = true;

			// 	if (metricSet == 2)
			// 		manyMetrics = true;

			// 	if (metricSet == 3){
			// 		manyMetrics = true;
			// 		appLabel = true;
			// 	}

			// 	if (metricSet == 4){
			// 		manyMetrics = true;
			// 		appLabel = true;
			// 		hostProfile = true;
			// 	}

			// 	if (metricSet == 5){
			// 		manyMetrics = true;
			// 		appLabel = true;
			// 		hostProfile = true;
			// 		queueMates = true;
			// 	}
			// 	if (fewMetrics)
			// 		std::cout << "#simple performance metrics" << std::endl;
			// 	if (manyMetrics)
			// 		std::cout << "#wide performance metric vector." << std::endl;
			// 	if (appLabel)
			// 		std::cout << "#application label." << std::endl;
			// 	if (hostProfile)
			// 		std::cout << "#host profile." << std::endl;
			// 	if (queueMates)
			// 		std::cout << "#queue mates." << std::endl;
			// }

			/*===============================
			=            digest (mCLFR) reading functions            =
			===============================*/
			// Load the eval data set into RAM. This would be done by the NIC. 
			void loadMicroflows(const char *inFile){

				FILE *f = fopen(inFile, "rb");
				fseek(f, 0, SEEK_END);
				long f_sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				// std::cout << "loading " << f_sz << " bytes of microflows." << std::endl;
				inBuf = (char *) malloc(f_sz);
				// std::cout << "finished mallocing" << std::endl;
				fread((char *)inBuf, f_sz, 1, f);
				fclose(f);
				// std::cout << "finished reading" << std::endl;
				bufPos = inBuf;
				bufEnd = inBuf + f_sz;
			}
			// Input args: metric set and mCLFR filename.
			explicit MetricBackend(int metricSet, int replicaId, const std::string& fn)
				: raft::kernel()
			{	

				rid = replicaId;
				// Load microflows into memory. 
				loadMicroflows(fn.c_str());
				// Read metadata (# of microflows. )
				ifstream insz;
				insz.open(fn + std::string(".len"), ios::binary);
				insz.read((char*)&totalMfCt, sizeof(totalMfCt));
				insz.close();
				CLFR_flatmap.reserve(234141);
				blankValue.flowFeatures = {0};
				blankValue.packetVector.reserve(4);


				// Load model from df.dat (11/19)
				loadModel();
				std::cout << "#metrics:" <<std::endl;
				if (metricSet == 1)
					fewMetrics = true;

				if (metricSet == 2)
					manyMetrics = true;

				if (metricSet == 3){
					manyMetrics = true;
					appLabel = true;
				}

				if (metricSet == 4){
					manyMetrics = true;
					appLabel = true;
					hostProfile = true;
				}

				if (metricSet == 5){
					manyMetrics = true;
					appLabel = true;
					hostProfile = true;
					queueMates = true;
				}
				if (fewMetrics)
					std::cout << "#simple performance metrics" << std::endl;
				if (manyMetrics)
					std::cout << "#wide performance metric vector." << std::endl;
				if (appLabel)
					std::cout << "#application label." << std::endl;
				if (hostProfile)
					std::cout << "#host profile." << std::endl;
				if (queueMates)
					std::cout << "#queue mates." << std::endl;

				// input.template add_port<T>("in");
				output.template addPort<double>("stats");
			}
			
			
			
			/*=====  End of digest (mCLFR) reading functions  ======*/
			



			void loadModel(){
				std::string modelFn("df.dat");
				std::cout << "#loading model from: " << modelFn << std::endl;
				deserialize(modelFn) >> df;

			}


			void computeStats(int fPos, std::vector<double> &v){
				// mean
				double sum = std::accumulate(std::begin(v), std::end(v), 0.0);
				double m =  sum / v.size();
				curFeatures(fPos)=m;

				// std dev
				double accum = 0.0;
				std::for_each (std::begin(v), std::end(v), [&](const double d) {
				    accum += (d - m) * (d - m);
				});
				double stdev = sqrt(accum / (v.size()-1));
				curFeatures(fPos+1)=m;

				// min
				double min_val = *std::min_element(std::begin(v), std::end(v));
				curFeatures(fPos+2)=min_val;

				// max
				double max_val = *std::max_element(std::begin(v), std::end(v));
				curFeatures(fPos+3)=max_val;

			}

			void getSimpleFeatures(std::pair<std::string, CLFR_Value> &CLFR_Pair){
				// Get the 3 vectors: packet inter-arrivals, inter-packet lengths, packet lengths
				for (int i = 0; i < (8+MINPKT_CT); i++){
					curFeatures(i) = 0;					
				}
				int vecLen = CLFR_Pair.second.packetVector.size();
				std::vector<double> interArrivals;
				interArrivals.reserve(vecLen);

				std::vector<double> packetLens;
				packetLens.reserve(vecLen);

				std::vector<double> interPacketLens;
				interPacketLens.reserve(vecLen);
				int idx = 0;
				int64_t lastTs, lastLen;				
				for (auto pktRec : CLFR_Pair.second.packetVector){
					if (idx != 0){
						interArrivals.push_back(pktRec.ts-lastTs);												
						interPacketLens.push_back(pktRec.byteCt - lastLen);						
					}
					packetLens.push_back(pktRec.byteCt);
					lastTs = pktRec.ts;
					lastLen = pktRec.byteCt;
					idx++;
				}
				// Compute 4 simple features based only on inter-Arivals.
				// Compute 4 features of each vec: minimum, maximum, mean, std dev
				// std::cout << "computing features" << std::endl;
				computeStats(0, interArrivals);
				computeStats(4, packetLens);
				computeStats(8, interPacketLens);
				for (int i = 0; i<min(MINPKT_CT, vecLen); i++){
					curFeatures(12+i)=packetLens[i];
				}
			}

			// Compute features.
			void getFeatures(std::pair<std::string, CLFR_Value> &CLFR_Pair){
				for (int i = 0; i < (8+MINPKT_CT); i++){
					curFeatures(i) = 0;					
				}
				// Get the 3 vectors: packet inter-arrivals, inter-packet lengths, packet lengths
				int vecLen = CLFR_Pair.second.packetVector.size();
				std::vector<double> interArrivals;
				interArrivals.reserve(vecLen);

				std::vector<double> packetLens;
				packetLens.reserve(vecLen);

				std::vector<double> interPacketLens;
				interPacketLens.reserve(vecLen);
				int idx = 0;
				int64_t lastTs, lastLen;				
				for (auto pktRec : CLFR_Pair.second.packetVector){
					if (idx != 0){
						interArrivals.push_back(pktRec.ts-lastTs);												
						interPacketLens.push_back(pktRec.byteCt - lastLen);						
					}
					packetLens.push_back(pktRec.byteCt);
					lastTs = pktRec.ts;
					lastLen = pktRec.byteCt;
					idx++;
				}
				// Compute 4 features of each vec: minimum, maximum, mean, std dev
				// std::cout << "computing features" << std::endl;
				computeStats(0, interArrivals);
				computeStats(4, packetLens);
				computeStats(8, interPacketLens);
				for (int i = 0; i<min(MINPKT_CT, vecLen); i++){
					curFeatures(12+i)=packetLens[i];
				}
			}

			// get class label based on features from prior function. 
			// requires getFeatures to be called ahead of time.
			void classifyFlow(){
				curFeatures = normalizer(curFeatures);

				auto predLabel = df(curFeatures);
				if (curLabel != 0.0){
					if (predLabel == curLabel){
						correctCounts[curLabel]++;
					}
					totalCounts[curLabel]++;
				}
			}

			// add timestamps to host profile.
			void buildHostProfile(std::pair<std::string, CLFR_Value> &kv){
				// extract key (source address)
				uint32_t key = *((uint32_t *) &(kv.first.c_str()[4]));
				// lookup into host table.
				auto got = hostTimes.find(key);
				if (got == hostTimes.end()){
					hostTimes[key] = blankValue_host;
					got = hostTimes.find(key);
				}
				// update profile.
				for (auto pfs : kv.second.packetVector){
					got->second.push_back(pfs.ts);
				}

			}

			// // Get training labels based on ports. 0 if not a class to train on.
			// void getLabel(std::pair<std::string, CLFR_Value> &CLFR_Pair){
			// 	uint16_t srcPort, dstPort;
			// 	srcPort = ntohs(*(uint16_t *)(CLFR_Pair.first.c_str()+8));
			// 	dstPort = ntohs(*(uint16_t *)(CLFR_Pair.first.c_str()+10));
			// 	// auto got = portClasses.find(srcPort);
			// 	// if (got != portClasses.end()){
			// 	// 	curLabel=got->second;
			// 	// 	return;
			// 	// }
			// 	auto got = portClasses.find(dstPort);
			// 	if (got != portClasses.end()){
			// 		curLabel=got->second;
			// 		return;					
			// 	}
			// 	curLabel = 0.0;
			// 	return;
			// }

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

			void getQueueMates(std::pair<std::string, CLFR_Value> &kv){
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
				// // for implementation: do queue processing for important flows. 					
				// uint32_t src = *(uint32_t *)(kv.first.c_str());
				// if (src > 20){
				// // for benchmark: do processing for all flows.
				if (1){
					// for benchmark: assume queue overflow events happen in a pct of the flows.
					uint32_t rNum = random() % 100;
					// std::cout << rNum << std::endl;						
					if (rNum <= QUEUE_WARN_PROB) {
						// std::cout << "rnum <=5" << std::endl;						
					// // for implementation: 
					// // if above threshold, and queue is growing, get the occupants in the queue.
					// if (localMaxSize >= queueThreshold){
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
						// cout << "occupants["<<kv.second.packetVector[0].ts<<"] = (" <<pctAboveThreshold << ", [ ";
						// for (auto h : uniqueOffenders){
						// 	cout << h <<",";
						// }
						// cout << "] )" << endl;
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

			}


			void processClfr(std::pair<std::string, CLFR_Value> &kv){
				// // only consider flows that are long enough for classification.
				// if (kv.second.packetVector.size() < MINPKT_CT){
				// 	// counter++;
				// 	continue;
				// }
				if(fewMetrics)
					// get simple features of the flow.
					getSimpleFeatures(kv);
				if(manyMetrics)
					// get features of the flow.
					getFeatures(kv);
				if(appLabel)
					// classify the flow.
					classifyFlow();
				if (hostProfile)
					buildHostProfile(kv);
				if (queueMates)
					getQueueMates(kv);
				counter++;				
			}


			// Check flows for timeouts. 
			void timeoutFlows(){
				for (auto kv : CLFR_flatmap){
					if (curTs - kv.second.packetVector.back().ts > timeoutThreshold){
						finCt++;
						auto CLFR = std::pair<std::string, CLFR_Value>(kv.first, kv.second);						
						processClfr(CLFR);
						CLFR_flatmap.erase(kv.first);
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


				// Read all microflows.
				while (mfCt < totalMfCt){
					// std::cout << "on mfCt: " << mfCt << std::endl;
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
					// A flow finished, so call the processing function.
					if (((flow_features->th_flags & TH_FIN) == TH_FIN) || ((flow_features->th_flags & TH_RST) == TH_RST)) {
						auto CLFR = std::pair<std::string, CLFR_Value>(keyStr, got->second);						
						processClfr(CLFR);
						// batchVec->emplace_back(keyStr, got->second);
						finCt++;
						CLFR_flatmap.erase(keyStr);
      				}

      				// check for timed-out flows.
					if (curTs - lastCheckTs > timeoutCheckPeriod){
						timeoutFlows();
					}

      				mfCt += 1;
				}
			}

			void flushFlowTable(){
				for (auto kv : CLFR_flatmap){
					finCt++;
					auto CLFR = std::pair<std::string, CLFR_Value>(kv.first, kv.second);
					processClfr(CLFR);
					// CLFR_flatmap.erase(keyStr);
				}
			}

			// The main processing loop.
			raft::kstatus run() override
			{
				// std::cout << "in run" << std::endl;
				startTs = high_resolution_clock::now();
				// Read microflows.
				readMicroflows();
				// std::cout << "flows processed before flush: " << finCt << std::endl;
				// Don't flush flow tables. All timed-out flows will have been processed.
				// For now: ignore flows that didn't time out normally.
				// Dump all remaining flows.
				// flushFlowTable();
				// std::cout << "flows processed after flush: " << finCt << std::endl;
				// log end time.
				endTs = high_resolution_clock::now();
				finalClfrCt = finCt;
				// report number of CLFRs and rate of this replica chain. (11/19)
				std::cout << "clfrCount[" << rid << "]="<<finalClfrCt<<std::endl;
				auto duration = duration_cast<milliseconds>( endTs - startTs).count();
				std::cout << "clfrRate[" << rid << "]="<<1000.0*(float(finalClfrCt)/float(duration))<<std::endl;
				return (raft::stop);
				output["stats"].push(1.0); // Don't need this.
			}

		};
	}
}

#endif
