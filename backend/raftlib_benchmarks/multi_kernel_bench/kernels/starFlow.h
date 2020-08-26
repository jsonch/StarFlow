#ifndef STARFLOW_CSTRUCTS
#define STARFLOW_CSTRUCTS


#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <list>
#include "MurmerHash3.h"
using namespace std;
uint64_t gpid = 0;

// Structs and support functions for *Flow. 


#define KEYLEN 13 // Length of key used in any flow tables. 


#define PKT_FTR_SZ 8
// Features of individual packet, for export from switch. 
struct PacketFeatures{
  uint16_t queueSize;
  uint16_t byteCt;
  uint32_t ts;
};


struct PacketRecord{
  char key[KEYLEN];
  u_char th_flags;
  PacketFeatures features;
};

// Maximum number of packet features that a micro-CLFR can hold. 
// (Will be truncated if < MCLFR_MAXLEN before switch export)
#define MCLFR_MAXLEN 32
struct MCLFR {
  // metadata.
  uint64_t hashVal;
  bool inUse;
  uint32_t lastAccessTs;
  uint64_t flowId;
  // key and aggregate features. 
  char key[KEYLEN];
  std::string keyStr;
  u_char th_flags;
  uint16_t pktCt;
  // per packet features.
  PacketFeatures packetVector[MCLFR_MAXLEN];
  // Index of long vector, if owned.
  uint32_t longVectorIdx;
};


// Key represented as ints for testing different hash tables.
// probably should be changed back to string.
struct PackedKey {
  uint64_t addrs;
  uint64_t portsproto;
};

struct FlowFeatures {
  uint32_t pktCt;
  u_char th_flags;
};

#define MF_HDR_SZ 24
// Format of switch export.
struct Export_MCLFR {
  char key[KEYLEN];
  // PackedKey packedKey;
  FlowFeatures flowFeatures;
  PacketFeatures packetVector[MCLFR_MAXLEN];
};

struct Export_MCLFR_hdr {
  char key[KEYLEN];
  // PackedKey packedKey;
  FlowFeatures flowFeatures;
};



// Internal CLFR format for applications. 
// ( previously named struct FlowRecord )
struct CLFR {
  char key[KEYLEN];
  FlowFeatures flowFeatures;
  // byte counts and timeStamps of each packet in the flow. 
  std::vector<uint16_t> queueSizes;
  std::vector<uint16_t> byteCounts;
  std::vector<uint32_t> timeStamps; 
};


struct CLFR_Value {
  FlowFeatures flowFeatures;
  // byte counts and timeStamps of each packet in the flow. 
  std::vector<PacketFeatures> packetVector;
  // std::vector<uint16_t> queueSizes;
  // std::vector<uint16_t> byteCounts;
  // std::vector<uint64_t> timeStamps; 
};

// struct CLFR_Value_Blob {
//   FlowFeatures flowFeatures;

// };

// void write_CLFR_Blob(char * outBuf, std::pair<std::string, CLFR_Value>& clfrTup){
//   memcpy(outBuf, clfrTup.first.c_str(), KEYLEN);
//   outBuf+=KEYLEN;
//   memcpy(outBuf, (char *) &clfrTup.second.flowFeatures, sizeof(CLFR_Value));
//   outBuf+=sizeof(CLFR_Value);
//   for (PacketFeatures p : clfrTup.second.packetVector){
//     memcpy(outBuf, (char *) &p, sizeof(PacketFeatures));
//     outBuf += sizeof(PacketFeatures);
//   }
//   return;
// }
// void read_CLFR_Blob()

void printSizes(){
  std::cout << "struct sizes" << std::endl;
  std::cout << "PacketFeatures:\t" << sizeof(PacketFeatures) << std::endl;
  std::cout << "PackedKey:\t" << sizeof(PackedKey) << std::endl;
  std::cout << "Export_MCLFR_hdr:\t" << sizeof(Export_MCLFR_hdr) << std::endl;
  std::cout << "Export_MCLFR:\t" << sizeof(Export_MCLFR) << std::endl;
  std::cout << "Export_MCLFR packetVector:\t" << MCLFR_MAXLEN*sizeof(PacketFeatures) << std::endl;
}



// Helpers.
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader);
uint64_t getMicrosecondTs(uint64_t seconds, uint64_t microSeconds);
MCLFR * newMicroflow(uint64_t curTs, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader);
unsigned simpleHash(unsigned int p, const char* s, int len, int maxHashVal);
std::string string_to_hex(const std::string& input);


// Convert a packet into a microflow with 1 item. 
void initMicroflow(MCLFR * mfr, uint64_t curTs, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  // Set raw key.
  setKey(mfr->key, ipHeader, udpOrtcpHeader);
  // Set aggregate features.
  mfr->pktCt = 1;
  // Set features of first packet vector slot. 
  mfr->packetVector[0].byteCt = ipHeader->ip_len;
  mfr->packetVector[0].ts = curTs;
}


// Get 64 bit timestamp.
uint64_t getMicrosecondTs(uint64_t seconds, uint64_t microSeconds){
  uint64_t ts = seconds * 1000000 + microSeconds;
  return ts;
}

void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  memcpy(&(keyBuf[0]), &ipHeader->ip_src, 4);
  memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  memcpy(&(keyBuf[8]), &udpOrtcpHeader->source, 2);
  memcpy(&(keyBuf[10]), &udpOrtcpHeader->dest, 2);
  memcpy(&(keyBuf[12]), &ipHeader->ip_p, 1);
}


// A simple hashing function.
unsigned simpleHash(unsigned int p, const char* s, int len, int maxHashVal)
{
    uint64_t out[2]; 
    MurmurHash3_x64_128(s, len, p, out);
    return out[1] % maxHashVal;
}

std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

#endif