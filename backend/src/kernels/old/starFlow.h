#ifndef STARFLOW_CSTRUCTS
#define STARFLOW_CSTRUCTS

#include <netinet/tcp.h>

#define KEYLEN        13 
#define MCLFR_MAXLEN  32
struct PacketFeatures{
  uint16_t queueSize;
  uint16_t byteCt;
  uint32_t ts;
};

struct FlowFeatures {
  uint32_t pktCt;
  u_char th_flags;
};

// Format of switch export.
struct Export_MCLFR {
  char key[KEYLEN];
  FlowFeatures flowFeatures;
  PacketFeatures packetVector[MCLFR_MAXLEN];
};

struct CLFR_Value {
  FlowFeatures flowFeatures;
  std::vector<PacketFeatures> packetVector;
};


// format of a clfr. This struct isn't used in the code, 
// its just here for reference. In the code, we pass 
// a <keystring, CLFR_Value> pair. 
struct CLFR {
  char key[KEYLEN];
  CLFR_Value record;
};

#endif