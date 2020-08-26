
#ifndef STARFLOW_KERNELS_FEATURE_CALCULATOR_ALLSTATS
#define STARFLOW_KERNELS_FEATURE_CALCULATOR_ALLSTATS

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

// Extracts simple features for application prediction.
// (example 2)

#define BENCHMARK 1
#define BENCHMARK_CT 1000000
#define STATS 1

// #define LOAD_MODEL 1

// How many flows to gather from each class.
#define TRAIN_CT 500

// minimum packet count for classification.
#define MINPKT_CT 8


// ML model stuff.
// Some ML classifiers.

namespace starflow {
	namespace kernels {
		template<typename T>
		class AllStatsFeatureCalculator : public raft::kernel
		{
		public:
			// 15 features -- pkt ct, byte ct, duration + 12 statistics
			typedef matrix<double,15,1> sample_type;
			typedef linear_kernel<sample_type> kernel_type;

			high_resolution_clock::time_point last, cur, start, end; 
			uint64_t startTs = 0;
			uint64_t endTs = 0;	

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

			explicit AllStatsFeatureCalculator()
				: raft::kernel()
			{
				last = high_resolution_clock::now();
				start = high_resolution_clock::now();
				input.template add_port<T>("in");
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

			// Compute features.
			void getFeatures(std::pair<std::string, CLFR_Value> &CLFR_Pair){
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

				// total size.
				double lsum = std::accumulate(std::begin(packetLens), std::end(packetLens), 0.0);
				curFeatures(12)=lsum;
				// total duration.
				curFeatures(13)=float(CLFR_Pair.second.packetVector[vecLen-1].ts)-float(CLFR_Pair.second.packetVector[0].ts);
				// total pkt ct.
				curFeatures(14)=float(vecLen);

				// for (int i = 0; i<MINPKT_CT; i++){
				// 	curFeatures(13+i)=packetLens[i];
				// }
				// // std::cout << "feature vector: " << curFeatures << std::endl;
			}

			// Get training labels based on ports. 0 if not a class to train on.
			void getLabel(std::pair<std::string, CLFR_Value> &CLFR_Pair){
				uint16_t srcPort, dstPort;
				srcPort = ntohs(*(uint16_t *)(CLFR_Pair.first.c_str()+8));
				dstPort = ntohs(*(uint16_t *)(CLFR_Pair.first.c_str()+10));
				// auto got = portClasses.find(srcPort);
				// if (got != portClasses.end()){
				// 	curLabel=got->second;
				// 	return;
				// }
				auto got = portClasses.find(dstPort);
				if (got != portClasses.end()){
					curLabel=got->second;
					return;					
				}
				curLabel = 0.0;
				return;
			}

			void learnFlow(){
				// Append to features vector. 
				if (curLabel!=0.0){
					// Only if this class needs more samples.
					if (sampleCounts[curLabel]<TRAIN_CT){
						samples.push_back(curFeatures);
						labels.push_back(curLabel);	
						sampleCounts[curLabel]++;					
					}
					else if (curLabel == 1.0 && sampleCounts[curLabel]<(TRAIN_CT)){
						samples.push_back(curFeatures);
						labels.push_back(curLabel);	
						sampleCounts[curLabel]++;											
					}
				}
			}

			std::pair<double, double> crossValidate(){
				// Cross validate params.
				cout << "doing cross validation" << endl;
				double bestVal = 0.0;
				double bestEps = 0.0;
				double bestC = 0.0;
				for (double epsilon = 0.00001; epsilon <= 0.1; epsilon *= 10)
				{
				    for (double C = 100; C < 400; C += 10)
				    {
				        // tell the trainer the parameters we want to use
				        svm_trainer.set_c(C);
				        svm_trainer.set_epsilon(epsilon);

				        auto something = cross_validate_multiclass_trainer(svm_trainer, samples, labels, 5);
				        double cvSum = 0;
				        for (int i = 0; i < portClasses.size(); i++){
				        	cvSum += something(i, i);
				        }
				        if (bestVal < cvSum){
				        	bestVal = cvSum;
				        	bestEps = epsilon;
				        	bestC = C;
				        }
				        cout << "epsilon: " << epsilon << "    C: " << C << " sum " << cvSum << endl;
				        cout << "     cross validation accuracy: "  << endl
				             << something;
				        cout << endl;
						cout << "best values: epsilon: " << bestEps << " C: " << bestC << endl;
				    }
				}	
				cout << "best values: epsilon: " << bestEps << " C: " << bestC << " value: " << bestVal << endl;
				return std::pair<double, double>(bestEps, bestC);
				exit(1);			
			}
			void buildModel(){
				std::cout << "got enough training samples, building model." << std::endl;
				std::string modelFn("df.dat");
				// Randomize samples.
				randomize_samples(samples, labels);
				// Normalize samples.
			    normalizer.train(samples);
				for (unsigned long i = 0; i < samples.size(); ++i)
				    samples[i] = normalizer(samples[i]); 

				#ifndef LOAD_MODEL
				std::cout << "rebuilding model and saving to: " << modelFn << std::endl;
				// Cross validate if params are unknown. 
				auto ec = crossValidate();
				// auto ec = std::pair<double, double>(0.000010, 380);
				svm_trainer.set_epsilon(ec.first);
				svm_trainer.set_c(ec.second);
				svm_trainer.set_max_iterations(10000*100);
				// cross validate with params to make sure the model makes sense.
		        cout << "cross validation: " << endl << cross_validate_multiclass_trainer(svm_trainer, samples, labels, 5) << endl;
		
				// train the decision function.
		        df = svm_trainer.train(samples, labels);
				serialize(modelFn) << df;
				#else
				std::cout << "loading model from: " << modelFn << std::endl;
				deserialize(modelFn) >> df;
				#endif
				modelBuilt = true;

		        cout << "test deserialized function: \n" << test_multiclass_decision_function(df, samples, labels) << endl;
			}
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

			raft::kstatus run() override
			{
				// get a referecne to the CLFR batch object. 
				auto &clfrVector(input["in"].template peek<T>());	
				// Learn, train, or classify each flow.
				for (auto kv : clfrVector){
					// only consider flows that are long enough for classification.
					if (kv.second.packetVector.size() < MINPKT_CT){
						counter++;
						continue;
					}
					if (kv.second.packetVector[0].ts < 60000000){
						counter++;
						continue;
					}
					// get features of the flow.
					getFeatures(kv);
					getLabel(kv);
					// Collect the right amount of samples.
					if (samples.size()<(TRAIN_CT*(portClasses.size()))){
						learnFlow();
					}
					else {
						// Build model.
						if (!modelBuilt){
							buildModel();
						}						
						// Classify flow.
						classifyFlow();
					}
					counter++;
				}
				input["in"].recycle(); // recycle to move to next item.

				// for benchmarking. 
				#ifdef BENCHMARK
				if (counter > BENCHMARK_CT){					
					// std::cout << "read " << counter << " CLFRs " << endl;
					// report throughput.
					cur = high_resolution_clock::now();
					auto duration = duration_cast<milliseconds>( cur - last ).count();
					std::cout << std::fixed << "time to compute features of " << BENCHMARK_CT << " CLFRs: " << duration <<" processing rate: " << 1000.0*(double(counter)/double(duration)) << std::endl;
					counter = 0;
					last = high_resolution_clock::now();
					#ifdef STATS
					if (modelBuilt){
						for (auto kv : portNames){
							double correctPct = double(correctCounts[kv.first])/double(totalCounts[kv.first]);
							std::cout << kv.second << ": " << correctPct << " " << totalCounts[kv.first] << std::endl;
						}
						std::cout << std::endl;
					}
					else {
						for (auto kv : portNames){
						std::cout << kv.second << ": "  << sampleCounts[kv.first] << std::endl;						
						}
						std::cout << std::endl;
					}
					#endif

				}
				#endif

				return (raft::proceed);
			}

			// void handleBatch(std::vector<T> batchVector){

			// }

			// // Dump records.
			// void dumpRecords(){
			// 	std::cout << "records to: " << outFileName << std::endl;
			// 	ofstream o;
			// 	o.open(outFileName, ios::binary);
			// 	uint64_t tsesWritten = 0;
			// 	for (auto kv : hostTimes){
			// 		uint64_t hostIp = uint64_t(kv.first);
			// 		uint64_t tsCt = uint64_t(kv.second.size());
			// 		o.write((char *) &hostIp, sizeof(hostIp));
			// 		o.write((char *) &tsCt, sizeof(tsCt));
			// 		for (auto ts : kv.second){
			// 			o.write((char *) &ts, sizeof(ts));
			// 			tsesWritten++;
			// 		}
			// 	}
			// 	o.close();
			// }

		};
	}
}

#endif
