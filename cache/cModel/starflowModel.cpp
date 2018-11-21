#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdlib.h>

#include <algorithm>    // std::max
#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream> // for ostringstream
#include <vector>
#include <deque>
#include <unordered_map>
#include <list>
using namespace std;

#include "starFlow.h"

// ./mCLFR_cache ~/datasets/caida2015/caida2015_02_dirA.pcap 60000 2 8192 5 2048 16
// ./mCLFR_cache ~/datasets/caida2015/caida2015_02_dirA.pcap 60000 8 8192 5 2048 16
// Arguments: 
// filename, training time, lru chain length 
// partition 1 length, partition 1 width 
// partition 2 length, partition 2 width

// Static options.
#define TRACETYPE 1 // Trace type: 0 = ethernet, 1 = ip4v (i.e., caida)
#define UPDATE_CT 10000 // Print stats every UPDATE_CT packets.

uint64_t maxLastAccessTs = 0;
uint64_t sumLastAccessTs = 0;
uint64_t gtOneSecondInCache = 0;
uint64_t gtFiveSecondInCache = 0;

char * outputFile = "mCLFRs.bin";
ofstream o;
bool dump = false;
// args.
char * inputFile;
uint64_t trainingTime, lruChainLen, partition1Len, partition1Width, partition2Len, partition2Width;

// table variables.
// number of LRU chains. 
uint64_t htLen;
// the fixed width cache.
// hash --> LRU chain (MCLFR, MCLFR, ...)
// the mclfr feature vectors are limited to partition1Width entries. 
MCLFR** LRUChains;

MCLFR oldCLFR;

// the long packet feature vectors.
// index --> (fixed len feature vector)
PacketFeatures** longVectors;

uint32_t stackTop = 0;
uint32_t *longVectorStack;


uint64_t lastLongUse[1024] = {0};
uint64_t accessCounts[1024]= {0};


// logging and output. 
uint64_t globalPktCt, globalMfCt;
uint64_t globalFinMfCt;
uint64_t allocFailEvicts, lruEvicts, oversizeEvicts, shortRollovers, longRollovers;

uint64_t startTs, curTs;

std::vector<Export_MCLFR> mCLFR_out;

void dumpCtFile();
void dumpMClfrs();
void readMClfrs(char * inputFile);
void printStats();
void checkCorrectness();
// PFE cache functions.
// set up the tables. 
void initTables(){
  // Set up the LRU chains. 
  htLen = partition1Len/lruChainLen;
  LRUChains = new MCLFR*[htLen];
  for (int i=0; i<htLen; i++){
    LRUChains[i] = new MCLFR[lruChainLen];
    memset(LRUChains[i], 0, sizeof(MCLFR)*lruChainLen);
  }
  // Set up the long packet feature vectors. 
  longVectors = new PacketFeatures*[partition2Len];
  for (int i = 0; i<partition2Len; i++){
    longVectors[i] = new PacketFeatures[partition2Width];
    memset(longVectors[i], 0, sizeof(PacketFeatures)*partition2Width);
  }
  // Set up the long vector stack. 
  // bottom entry of stack should never be touched. 
  longVectorStack = new uint32_t[partition2Len];
  for (int i=0; i<partition2Len; i++){
    longVectorStack[stackTop] = i;
    stackTop++;
  }
  stackTop--;
}

#define SLOT_MATCH 0
#define SLOT_FREE 1
#define SLOT_EVICT 2

int slotType; // match, free, evict flag.
uint64_t getSlotId();

// processing logic.
void initMfr();
void evictMfr();
void shortAppend();
void longAppend();
void exportMfr();

// helpers.
void allocLongPointer();
void appendRecord();

// main.
void handlePacket();

// cleanup.
void finalFlush();

PacketRecord pr; // current packet record.
MCLFR evictedMFR; // mCLFR that is going to be evicted.

uint64_t hashVal;
uint64_t slotId;

// main packet processing function. 
void handlePacket(){
  globalPktCt++;


  // Compute hash. 
  hashVal = simpleHash(1, pr.key, KEYLEN, htLen);
  // Get the layer 1 slot -- either a match, free slot, or oldest entry. 
  // get slot id. 
  slotId = getSlotId();
  // cout << "hash value: " << hashVal << " slot id: " << slotId << endl;
  // if (hashVal == 29 && slotId == 0){
  //   cout << "29 PKT ARRIVAL pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;
  // }
  // Main processing pipeline.

  switch(slotType) {

    // FREE SLOT pipeline -- just set new record. 
    case SLOT_FREE:
      // cout << "initializing ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;
      initMfr();
      break;
    // EVICT SLOT pipeline -- read prior record, free prior long pointer, set record.
    case SLOT_EVICT:
      // cout << "evicting ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;
      evictMfr();
      initMfr();
      exportMfr();
      break;
    // MATCH SLOT pipeline -- append to short, alloc+append long, or append to long.      
    case SLOT_MATCH:
      // cout << "incrementing ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;

      // get the long pointer if eligible.
      allocLongPointer();

      if (LRUChains[hashVal][slotId].longVectorIdx == 0) {
        shortAppend();
      }
      else {
        longAppend();
      }
      break;
    default:
      cout << "invalid switch case" << endl;
  }

  // Stats stuff. 
  if (globalPktCt % UPDATE_CT == 0){
    printStats();
  }

  if ((trainingTime > 0) && ((curTs) > trainingTime*1000)){
    cout << "exiting training." << endl;
    printStats();

    if (dump){
      finalFlush();
      dumpCtFile();
      // dumpMClfrs();
    }
    exit(0);
  }
  // exit(1);

}

uint64_t getSlotId(){
  // Scan list for match, inUse entry, or oldest entry.  
  bool hasMatch = false;
  uint64_t matchPos;
  bool hasFree = false;
  uint64_t freePos;
  uint64_t oldestPos;
  uint64_t oldestTs = curTs+1;

  for (int cPos = 0; cPos < lruChainLen; cPos++){
    // cout << "\tcPos: " << cPos << endl;
    // printMfrInfo(LRUChains[hashVal][cPos]);
    // Check match. 
    if (memcmp(LRUChains[hashVal][cPos].key, pr.key, KEYLEN) == 0){
      hasMatch = true;
      matchPos = cPos;
      break;
    }
    // Check for older entry. 
    // cout << "\ttses: " << LRUChains[hashVal][cPos].lastAccessTs << " vs " << oldestTs << endl;
    if (LRUChains[hashVal][cPos].lastAccessTs < oldestTs) {
      oldestTs = LRUChains[hashVal][cPos].lastAccessTs;
      oldestPos = cPos;
      // cout << "\toldestPos1: " << oldestPos << endl;
    }
    // Check for null entry. 
    if (!hasFree && (!LRUChains[hashVal][cPos].inUse)){
      hasFree = true;
      freePos = cPos;
    }
  }
  if (hasMatch){
    slotType=SLOT_MATCH;
    // cout << "\tmatchPos: " << matchPos << endl;
    return matchPos;
  }
  else if (hasFree){
    slotType=SLOT_FREE;
    // cout << "\tfreePos: " << freePos << endl;
    return freePos;
  }
  else {
    slotType=SLOT_EVICT;
    // cout << "\toldestPos: " << oldestPos << endl;
    return oldestPos;
  }

  // 
}



// Final evict.
void finalFlush(){
  uint64_t finalFlushCt = 0;
  for (int i = 0; i<htLen; i++){
    for (int j = 0; j<lruChainLen; j++){
      if (LRUChains[i][j].inUse){
        finalFlushCt++;
        hashVal = i;
        slotId = j;
        evictMfr();
        exportMfr();
      }
    }
  }
  cout << "flushed " << finalFlushCt << " entries " << endl;

}


// dump all the MCLFRs to a file. 
void dumpMClfrs(){
  //Export_MCLFR
  cout << "dumping mCLFRs to: " << outputFile << endl;
  // ofstream o(outputFile, ios::binary);
  uint64_t ct = mCLFR_out.size();
  o.write((char*)&ct, sizeof(ct));
  for (auto mclfr : mCLFR_out){
    o.write((char*)&mclfr.packedKey, KEYLEN);
    o.write((char*)&mclfr.flowFeatures.th_flags, sizeof(mclfr.flowFeatures.th_flags));
    o.write((char*)&mclfr.flowFeatures.pktCt, sizeof(mclfr.flowFeatures.pktCt));
    o.write((char*)mclfr.packetVector, sizeof(PacketFeatures)*mclfr.flowFeatures.pktCt);
  }
  cout << "\twrote " << ct << " mCLFRs" << endl;
  o.close();

  // Make sure its right. 
  // readMClfrs(outputFile);
}

void dumpCtFile(){
  cout << "\twrote " << globalMfCt << " mCLFRs to " << outputFile << endl;
  o.close();
  ofstream osz(string(outputFile)+string(".len"), ios::binary);
  cout <<"\twrote value " << globalMfCt << " to " << string(outputFile)+string(".len") << endl;
  osz.write((char*)&globalMfCt, sizeof(globalMfCt));
  osz.close();

  // readMClfrs(outputFile);
}

// // Read mCLFRs and reassembly into vector format.
// void readMClfrs(char * inputFile){
//   cout << "reading mCLFRs from: " << inputFile << endl;
//   uint64_t ct = 0;
//   Export_MCLFR inMclfr;
//   ifstream insz(string(inputFile)+string(".len"), ios::binary);
//   insz.read((char*)&ct, sizeof(ct));
//   insz.close();
//   cout << "reading " << ct << " mCLFRs" << endl;

//   ifstream in(inputFile, ios::binary);
//   std::unordered_map<std::string, CLFR> CLFRTable;
//   std::unordered_map<std::string, CLFR> CLFRTable_fin;
//   CLFR tmpClfr;
//   Export_MCLFR tmpMClfr;
//   for (int i=0; i<ct; i++){
//     // read header values into tmp clfr.
//     in.read((char*)tmpClfr.key, KEYLEN);
//     in.read((char*)&tmpClfr.th_flags, sizeof(tmpClfr.th_flags));
//     in.read((char*)&tmpMClfr.pktCt, sizeof(tmpMClfr.pktCt));
//     tmpClfr.pktCt = (uint32_t)tmpMClfr.pktCt;
//     tmpClfr.keyStr = std::string(tmpClfr.key, KEYLEN);

//     // emplace tmp clfr into map. 
//     CLFRTable.emplace(tmpClfr.keyStr, tmpClfr);

//     // evict here based on TCP flag.

//     // read features into tmp vector.
//     in.read((char*)tmpMClfr.packetVector, sizeof(PacketFeatures)*tmpMClfr.pktCt);
//     // iterate through features and insert. 
//     for (int j = 0; j<tmpClfr.pktCt; j++){
//       CLFRTable[tmpClfr.keyStr].byteCounts.push_back(tmpMClfr.packetVector[j].byteCt);
//       CLFRTable[tmpClfr.keyStr].timeStamps.push_back(tmpMClfr.packetVector[j].ts);
//       CLFRTable[tmpClfr.keyStr].queueSizes.push_back(tmpMClfr.packetVector[j].queueSize);
//     }
//   }
//   cout << "done reading microflows" << endl;
//   // Done. 
//   in.close();
// }

void printStats(){
  cout << "---------------------- trace time (usec): " << curTs << " ----------------------" << endl; 
  cout << "\t # packets processed: " << globalPktCt << endl;
  cout << "\t # GPVs generated: " << globalMfCt << endl;
  cout << "\t GPV to packet ratio: " << float(globalMfCt) / float(globalPktCt) << endl;
  cout << "\t # evicts: " << lruEvicts << endl; 
  cout << "\t # rollovers in short partition: " << shortRollovers << endl;
  cout << "\t # rollovers in long partition: " << longRollovers << endl;
  // cout << "\t mfs with fin flags: " << globalFinMfCt << endl;
  cout << "\t avg time in cache (usec): " << (sumLastAccessTs/globalMfCt) <<endl;
  cout << "\t max time in cache: " << maxLastAccessTs << endl;
  cout << "\t # flows that spent more than 1 second in cache: " << gtOneSecondInCache << endl;
  cout << "\t # flows that spent more than 5 seconds in cache: " << gtFiveSecondInCache << endl;
  cout << "------------------------------------------------------------------" << endl;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[]){
  if (argc != 8){
    cout << "incorrect number of arguments. Need 7. filename, training time, lru chain length, partition 1 length, partition 1 width, partition 2 length, partition 2 width." << endl;
    exit(0);
  }
  inputFile = argv[1];
  cout << "reading from file: " << inputFile << endl;
  trainingTime = atoi(argv[2]);
  lruChainLen = atoi(argv[3]);
  partition1Len = atoi(argv[4]);
  partition1Width = atoi(argv[5]);
  partition2Len = atoi(argv[6]);
  partition2Width = atoi(argv[7]);
  cout << "params: " << " trainingTime: " << trainingTime << " lruChainLen: " << lruChainLen << " partition1Len:" << partition1Len << " partition1Width: " << partition1Width << " partition2Len: " << partition2Len << " partition2Width: " << partition2Width << endl;

  initTables();
  cout << "tables initialized." << endl;

  if (dump){
    cout << "dumping mCLFRs to: " << outputFile << endl;
    o.open(outputFile, ios::binary);
  }

  // Process packets. 
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  // open capture file for offline processing
  descr = pcap_open_offline(inputFile, errbuf);
  if (descr == NULL) {
      cerr << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }
  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      cerr << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }
  cout << "done processing." << endl;
  cout << "FINAL STATS:" << endl;
  printStats();
  if (dump){
    finalFlush();
    dumpCtFile();
    // dumpMClfrs();
  }
  exit(0);

  return 0;
}

// The packet handler that implements the flow record generator. 
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  const struct udphdr* udpHeader;


  // Set global timestamp relative to start of pcap. 
  if (startTs == 0) startTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
  curTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) - startTs;


  // Get IP header.
  if (TRACETYPE == 0){
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    }
  }
  else if (TRACETYPE == 1) {
    ipHeader = (struct ip*)(packet);

  }

  // Parse packet into microflow format. 
  if (ipHeader->ip_p == 6){
    tcpHeader = (tcphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    // Set raw key.
    setKey(pr.key, ipHeader, (const udphdr*)tcpHeader);
    pr.th_flags = tcpHeader->th_flags;
    pr.features.byteCt = ipHeader->ip_len;
    pr.features.ts = curTs;
    pr.features.queueSize = 1;

    handlePacket();
  }

  else if (ipHeader->ip_p == 17){
    udpHeader = (udphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    // Set raw key.
    setKey(pr.key, ipHeader, udpHeader);
    pr.th_flags = 0;
    pr.features.byteCt = ipHeader->ip_len;
    pr.features.ts = curTs;
    pr.features.queueSize = 1;

    handlePacket();
  }

}


/*=================================
=            New stuff            =
=================================*/



void initMfr(){
    LRUChains[hashVal][slotId].firstAccessTs = curTs;
    // set key. 
    memcpy(LRUChains[hashVal][slotId].key, pr.key, KEYLEN);
    // set flow features.
    LRUChains[hashVal][slotId].pktCt = 0;

    // append packet features.
    appendRecord();

    // set processing state.
    LRUChains[hashVal][slotId].inUse = true;
    LRUChains[hashVal][slotId].allocAttempt = false; // never tried alloc.
    LRUChains[hashVal][slotId].longVectorIdx = 0;    


}


void evictMfr() {
    lruEvicts++;
    // cout << "\tevict called on ( " << hashVal << ", " << slotId << " )" << endl;
    // cout << "evicting MFR" << endl;
    memcpy(&evictedMFR, &(LRUChains[hashVal][slotId]), sizeof(evictedMFR));
    evictedMFR.pktCt += 1; // Correct packet count, when evict, it represent the last packet ID.
    // If it was previously allocated a partition 2, free it.
    if (LRUChains[hashVal][slotId].longVectorIdx != 0){
      // cout << "freeing long vector ( " << hashVal << ", " << slotId << " )" << endl;
      stackTop++;
      longVectorStack[stackTop] = LRUChains[hashVal][slotId].longVectorIdx;
      LRUChains[hashVal][slotId].longVectorIdx = 0;
    }
    LRUChains[hashVal][slotId].inUse = false;
}

void allocLongPointer() {
  if ( LRUChains[hashVal][slotId].allocAttempt == false 
    && (LRUChains[hashVal][slotId].pktCt+1) == partition1Width ) {
    LRUChains[hashVal][slotId].allocAttempt = true;
    if (stackTop > 0){
      // cout << "claiming long vector ( " << hashVal << ", " << slotId << " )" << endl;
      // cout << "\tgot long vector index: " << myLongVectorIdx << " from stack pos: " << stackTop << endl;
      LRUChains[hashVal][slotId].longVectorIdx = longVectorStack[stackTop];
      stackTop--;
    } else {
      LRUChains[hashVal][slotId].longVectorIdx = 0;
    }     
  }
}

void appendRecord() {
    LRUChains[hashVal][slotId].packetVector[LRUChains[hashVal][slotId].pktCt] = pr.features;  
    LRUChains[hashVal][slotId].th_flags = LRUChains[hashVal][slotId].th_flags | pr.th_flags;
    LRUChains[hashVal][slotId].lastAccessTs = curTs;  
}

void shortAppend() {
  // Increment packet id.
  LRUChains[hashVal][slotId].pktCt += 1;
  // If pktCt % partition1Width == 0, do a short rollover: export current record, overwrite it.
  if (LRUChains[hashVal][slotId].pktCt % partition1Width == 0) {
      memcpy(&evictedMFR, &(LRUChains[hashVal][slotId]), sizeof(evictedMFR));     
    LRUChains[hashVal][slotId].pktCt = 0;
    exportMfr();
    shortRollovers++;
  }
  // append the record for this packet.
  appendRecord();
}

void longAppend() {
  // Increment packet id.
  LRUChains[hashVal][slotId].pktCt += 1;
  // If pktCt % (partition1Width+partition2Width) == 0, do a long rollover: export current record, overwrite it.
  if (LRUChains[hashVal][slotId].pktCt % (partition1Width+partition2Width) == 0) {
      memcpy(&evictedMFR, &(LRUChains[hashVal][slotId]), sizeof(evictedMFR));     
    LRUChains[hashVal][slotId].pktCt = 0;
    exportMfr();
    longRollovers++;
  }
  // append the record for this packet.
  appendRecord();
}

// convert to export format, increment counters, write to file, etc.
void exportMfr(){
  if (dump){
    Export_MCLFR outMclfr; 
    // Copy to packed key.
    memcpy((char*)&outMclfr.packedKey.addrs, evictedMFR.key, 8);
    memcpy((char*)&outMclfr.packedKey.portsproto, evictedMFR.key+8, 4);
    memcpy((char*)&outMclfr.packedKey.portsproto, evictedMFR.key+12, 1);

    // Copy flow features. 
    outMclfr.flowFeatures.pktCt = (uint32_t)evictedMFR.pktCt;
    outMclfr.flowFeatures.th_flags = evictedMFR.th_flags;

    if (((outMclfr.flowFeatures.th_flags & TH_FIN) == TH_FIN) || ((outMclfr.flowFeatures.th_flags & TH_RST) == TH_RST)) {
      globalFinMfCt++;
    }
    // copy packet features. 
    memcpy(outMclfr.packetVector, evictedMFR.packetVector, sizeof(PacketFeatures)*outMclfr.flowFeatures.pktCt);

    // don't store vector.
    // mCLFR_out.push_back(outMclfr);

    // print timestamps..
    // std::cout << "cur ts: " << curTs << " evicted pkt ct: " << outMclfr.flowFeatures.pktCt <<  " evicted last ts: " << outMclfr.packetVector[outMclfr.flowFeatures.pktCt-1].ts << std::endl;
    if (outMclfr.packetVector[outMclfr.flowFeatures.pktCt-1].ts>curTs){
      std::cout << " time traveller" << std::endl;
      exit(1);
    }

    Export_MCLFR t1;
    Export_MCLFR_hdr t2;
    // cout << "whole struct: " << sizeof(t1) << " hdr: " << sizeof(t2) << " array: " << sizeof(t1.packetVector) << " individual pkt features: " << sizeof(PacketFeatures) * MCLFR_MAXLEN << endl;
    // exit(1);
    // Write to output file.
    if (dump){ 
      o.write((char*)&outMclfr.packedKey, sizeof(outMclfr.packedKey));
      o.write((char*)&outMclfr.flowFeatures, sizeof(outMclfr.flowFeatures));
      // Only write the filled features!
      o.write((char*)outMclfr.packetVector, sizeof(PacketFeatures)*outMclfr.flowFeatures.pktCt);
    }
  }
  uint64_t inCacheTime = curTs - evictedMFR.firstAccessTs;
  maxLastAccessTs = std::max(maxLastAccessTs, inCacheTime);
  sumLastAccessTs += inCacheTime;
  if (inCacheTime > 1000000) {
    gtOneSecondInCache++;
  }
  if (inCacheTime > 5000000) {
    gtFiveSecondInCache++;
  }


  globalMfCt++;
}


/*=====  End of New stuff  ======*/
