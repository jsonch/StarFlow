// Calculate flow statistics from clfrs. 
// This is an example of a lightweight kernel
// (it doesn't spend much time on each item)
#ifndef STARFLOW_KERNELS_FEATURE_CALCULATOR
#define STARFLOW_KERNELS_FEATURE_CALCULATOR

#include <iostream>
#include <fstream>
#include <numeric>
#include <algorithm>  
#include <netinet/in.h>
#include <unordered_map>

#include <chrono>
#include <vector>
using namespace std;
using namespace std::chrono;

// include FLOW_FEATURE_CT aggregate features and 
// packet-level features from MEAS_PKT_CT in each flow
#define FLOW_FEATURE_CT 12
#define MEAS_PKT_CT 	8

namespace starflow {
	namespace kernels {
		template<typename T>
		class FeatureCalculator : public raft::kernel
		{
		public:

			// Output: batches of (key, featureVec) pairs
			using output_t = std::vector<std::pair<std::string, std::vector<double>>>;

			explicit FeatureCalculator()
				: raft::kernel()
			{
				input.template add_port<T>("in");
				output.template add_port<output_t>("out");
			}

			void computeStats(std::vector<double> &featureVec, std::vector<double> &v){
				// mean
				double sum = std::accumulate(std::begin(v), std::end(v), 0.0);
				double m =  sum / v.size();
				featureVec.push_back(m);

				// std dev
				double accum = 0.0;
				std::for_each (std::begin(v), std::end(v), [&](const double d) {
				    accum += (d - m) * (d - m);
				});
				double stdev = sqrt(accum / (v.size()-1));
				featureVec.push_back(stdev);

				// min
				double min_val = *std::min_element(std::begin(v), std::end(v));
				featureVec.push_back(min_val);

				// max
				double max_val = *std::max_element(std::begin(v), std::end(v));
				featureVec.push_back(max_val);
			}

			// Compute flow feature vector
			void getFeatures(std::vector<double> &featureVec, CLFR_Value &clfrRec){
				// Get the 3 vectors: packet inter-arrivals, inter-packet lengths, packet lengths
				featureVec.reserve(FLOW_FEATURE_CT + MEAS_PKT_CT);
				int vecLen = clfrRec.packetVector.size();
				std::vector<double> interArrivals;
				interArrivals.reserve(vecLen);

				std::vector<double> packetLens;
				packetLens.reserve(vecLen);

				std::vector<double> interPacketLens;
				interPacketLens.reserve(vecLen);
				int idx = 0;
				int64_t lastTs, lastLen;				
				for (auto pktRec : clfrRec.packetVector){
					if (idx != 0){
						interArrivals.push_back(pktRec.ts-lastTs);												
						interPacketLens.push_back(pktRec.byteCt - lastLen);						
					}
					packetLens.push_back(pktRec.byteCt);
					lastTs = pktRec.ts;
					lastLen = pktRec.byteCt;
					idx++;
				}
				// Compute 4 features from each vec: minimum, maximum, mean, std dev
				computeStats(featureVec, interArrivals);
				computeStats(featureVec, packetLens);
				computeStats(featureVec, interPacketLens);

				for (int i = 0; i<min(MEAS_PKT_CT,vecLen); i++){
					featureVec.push_back(packetLens[i]);
				}
			}
			raft::kstatus run() override
			{
				// allocate new output vector.
				auto &out( output["out"].template allocate<output_t>() );
				auto batchVec = &out;
				batchVec->reserve(BATCH_SIZE_READER);
				auto &clfrVector(input["in"].template peek<T>());					
				for (auto kv : clfrVector) {
					std::vector<double> featureVec;
					batchVec->emplace_back(kv.first, featureVec);
					getFeatures(batchVec->back().second, kv.second);					
				}
				input["in"].recycle();
				output["out"].send();
				return (raft::proceed);
			}
		};
	}
}

#endif
