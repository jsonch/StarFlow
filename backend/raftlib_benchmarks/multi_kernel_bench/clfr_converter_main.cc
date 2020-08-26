
#include <raft>
#include <raftio>

#include "kernels/microflow_reader.h"
// #include "kernels/clfr_reader.h"
#include "kernels/clfr_counter.h"

#include "kernels/microburst_detector.h"

#include "kernels/cloner.h"

#include "kernels/clfr_counter_replicated.h"

#include "kernels/benchmark_printer.h"

#include "kernels/tap.h"
#include "kernels/benchmark_printer.h"


#include <cstdint>
#include <iostream>
#include <fstream>



void runReplicas(int N){
  raft::map m;  



  starflow::kernels::MicroflowReader * readers[N];
  // starflow::kernels::ClfrCounterReplicated<starflow::kernels::MicroflowReader::output_t> * counters[N];
  starflow::kernels::ClfrCounter<starflow::kernels::MicroflowReader::output_t> * counters[N];
  starflow::kernels::BenchmarkPrinter<double> logger(N);


  starflow::kernels::ClfrTap<starflow::kernels::MicroflowReader::output_t> * taps[N];
  // starflow::kernels::ClfrTap<starflow::kernels::MicroflowReader::output_t> mfTap(N);
  for (int i=0; i<N/1; i++){
    taps[i] = new starflow::kernels::ClfrTap<starflow::kernels::MicroflowReader::output_t>(1);

  }

  for (int i=0; i<N; i++){
    // readers[i] = new starflow::kernels::MicroflowReader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs11.bin");
    // m += *(readers[i]) >> mfTap[std::to_string(i)];

    readers[i] = new starflow::kernels::MicroflowReader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin");
    // readers[i] = new starflow::kernels::MicroflowReader("/home/jsonch/gits/starflow_analytics/inputs/caida2015_02_dirA.mCLFRs.bin");


    m += (*(readers[i]))["out"] >> (*(taps[(i/1)]))[std::to_string(i%1)];
    // counters[i] = new starflow::kernels::ClfrCounterReplicated<starflow::kernels::MicroflowReader::output_t>(i);
    // counters[i] = new starflow::kernels::ClfrCounter<starflow::kernels::MicroflowReader::output_t>;

    // m += (*(readers[i]))["out"] >> (*(taps[i]))[std::to_string(i/2)];
    // m += (*(readers[i]))["out"] >> *(counters[i]);
    m += (*(readers[i]))["stats"] >> logger[std::to_string(i)];
  }

  m.exe();  

}

    // counters[i] = new starflow::kernels::ClfrCounterReplicated<starflow::kernels::MicroflowReader::output_t>(i);
    // m += *(readers[i]) >> *(counters[i]);

void benchmarkReplicas(){
  for (int i = 1; i<=32; i = i*2){
    std::cout << "# testing " << i << " replicas" << endl;
    std::cout << "# ------------ " << endl;
    runReplicas(i);
    std::cout << "# ------------ " << endl;
  }

}

void runClones(int N){
  raft::map m;
  // starflow::kernels::ClfrReader reader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin.clfrs");  
  starflow::kernels::MicroflowReader reader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin");

  // Clone CLFRs to multiple counters.
  starflow::kernels::ClfrCloner<starflow::kernels::MicroflowReader::output_t> cloner(N);
  m += reader >> cloner;
  starflow::kernels::ClfrCounter<starflow::kernels::MicroflowReader::output_t> counters[N];
  for (int i = 0; i<N; i++){
    m += cloner[std::to_string(i)] >> counters[i];
  }
  std::cout << "executing kernels." << endl;
  m.exe();
}


int main(int argc, char** argv)
{
  benchmarkReplicas();
  return 0;
  // // runClones(3);
  // return 1;
  // runReplicas(1);
  // benchmarkReplicas();
  // return 1;
  std::cout << "initializing kernels." << endl;
  // The kernel to read CLFRs. Emits CLFRs.
  // starflow::kernels::MicroflowReader reader("/home/jsonch/gits/starflow_analytics/inputs/caida2015_02_dirA.mCLFRs.bin");
  // starflow::kernels::MicroflowReader reader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs_small2.bin");
  starflow::kernels::MicroflowReader reader("/home/jsonch/gits/starflow_analytics/inputs/mCLFRs.32.bin");

  // A counter to process output from the reader. Does not emit anything. 
  // The counter is typed by the kind of object it reads. 
  starflow::kernels::ClfrCounter<starflow::kernels::MicroflowReader::output_t> counter;
  // starflow::kernels::MicroburstDetector<starflow::kernels::MicroflowReader::output_t> detector;
  std::cout << "executing kernels." << endl;
  // Connect the kernels and execute. 
  raft::map m;
  starflow::kernels::BenchmarkPrinter<double> logger(1);

  // m += reader >> counter;
  m += reader["out"] >> counter;
  m += reader["stats"] >> logger;
  m.exe();
  // m += subscriber >> ip_source_timestamps >> sink;
  // m.exe();

  return 0;
}
