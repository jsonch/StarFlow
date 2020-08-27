// benchmark throughput (in packets per second) of a kernel 
// that groups mCLFRs into CLFRs.
#include <raft>
#include <raftio>

#include <cstdint>
#include <iostream>
#include <fstream>

#include "kernels/microflow_reader.h"

#include "kernels/clfr_writer.h"
#include "kernels/clfr_reader.h"

#include "kernels/packet_rate.h"
#include "kernels/flow_rate.h"
#include "kernels/benchmark_printer.h"

#include "kernels/feature_calculator.h"

#include "kernels/microburst_detector.h"

#include "kernels/sink.h"

void benchmarkMclfrReader(const char * inFn);
void generateClfrs(const char * inFn, const char * clfrFn);
void benchmarkClfrReader(const char * clfrFn);

void benchmarkFlowMeasApp(const char * clfrFn);

void benchmarkMicroburstApp(const char *clfrFn); 

int main(int argc, char** argv) {
  const char * inFn = "inputs/mCLFRs.32.bin";
  const char * clfrFn = "mCLFRs.32.clfr";
  generateClfrs(inFn, clfrFn);

  benchmarkMclfrReader(inFn);

  benchmarkClfrReader(clfrFn);  

  // note that this benchmark reports in FLOWS per second, not packets!
  benchmarkFlowMeasApp(clfrFn);

  // Test the microburst detector on a synthetic trace that actually has microbursts.
  const char * mbClfrFn = "inputs/microburst.clfrs.bin";
  benchmarkMicroburstApp(mbClfrFn);
  return 0;
}


// benchmark a single mclfr reader.
void benchmarkMclfrReader(const char * inFn) {
  cout << "# ---------------" << endl;
  std::cout << "# benchmarking a single micro-clfr reader" << endl;
  std::cout << "# initializing kernels." << endl;
  // read mclfrs and convert to clfrs
  starflow::kernels::MicroflowReader reader(inFn);
  // measure stream rate in packets per second
  starflow::kernels::MeasurePacketRate<starflow::kernels::MicroflowReader::output_t> counter;
  // print results
  starflow::kernels::BenchmarkPrinter<double> pktRateLogger(1, "pkts_per_second");

  std::cout << "# executing kernels." << endl;

  raft::map m;
  m += reader["out"] >> counter >> pktRateLogger;
  m.exe();
  cout << "# ---------------" << endl;
}

// convert mCLFRs to CLFRs.
void generateClfrs(const char * inFn, const char * clfrFn) {
  cout << "# ---------------" << endl;
  cout << "# converting micro-clfrs to clfrs" << endl;
  // read mclfrs and convert to clfrs.
  starflow::kernels::MicroflowReader reader(inFn);
  // write clfrs.
  starflow::kernels::ClfrWriter<starflow::kernels::MicroflowReader::output_t> writer(clfrFn);

  raft::map m;
  m += reader >> writer;
  m.exe();
  cout << "# ---------------" << endl;
}

void benchmarkClfrReader(const char * clfrFn) {
  cout << "# ---------------" << endl;
  std::cout << "# benchmarking a single clfr reader" << endl;
  // Read clfrs
  starflow::kernels::ClfrReader reader(clfrFn);  
  // measure stream rate in packets per second
  starflow::kernels::MeasurePacketRate<starflow::kernels::MicroflowReader::output_t> counter;
  // print results
  starflow::kernels::BenchmarkPrinter<double> pktRateLogger(1, "packets_per_second");

  std::cout << "# executing kernels." << endl;

  raft::map m;
  m += reader["out"] >> counter >> pktRateLogger;
  m.exe();
  cout << "# ---------------" << endl;
}

// Benchmark an application that calculates 20 flow metrics from each clfr. 
// (These metrics can be features for a classifier.)
void benchmarkFlowMeasApp(const char * clfrFn) {
  cout << "# ---------------" << endl;
  std::cout << "# benchmarking flow meas clfr app" << endl;
  // Read clfrs
  starflow::kernels::ClfrReader reader(clfrFn);  

  // // Measure per-flow stats from clfrs.
  starflow::kernels::FeatureCalculator
    <starflow::kernels::ClfrReader::output_t> calc;

  // print output stream throughput (in flows / sec)
  starflow::kernels::MeasureFlowRate
    <std::vector<std::pair<std::string, std::vector<double>>>> ctr;

  starflow::kernels::BenchmarkPrinter<double> lgr(1, "flows_per_second");

  std::cout << "# executing kernels." << endl;

  raft::map m;
  m += reader["out"] >> calc >> ctr >> lgr;
  m.exe();
  cout << "# ---------------" << endl;
}

// Benchmark an application to identify the hosts 
// responsible for microbursts
void benchmarkMicroburstApp(const char * clfrFn) {
  cout << "# ---------------" << endl;
  std::cout << "# benchmarking microburst clfr app" << endl;
  // Read clfrs
  starflow::kernels::ClfrReader reader(clfrFn);  

  starflow::kernels::MicroburstDetector<starflow::kernels::ClfrReader::output_t> detector; 

  starflow::kernels::Sink<std::unordered_set<uint32_t>> sink;
  starflow::kernels::BenchmarkPrinter<double> pktRateLogger(1, "pkts_per_second");


  raft::map m;
  m += reader["out"] >> detector;
  m += detector["out"] >> sink;
  m += detector["stats"] >> pktRateLogger;
  m.exe();
  cout << "# ---------------" << endl;
}

