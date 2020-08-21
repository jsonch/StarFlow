/**
 *
 * mainStarFlow.p4 -- Simple 2 hop switch with StarFlow.
 * 
 */

#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/primitives.p4>

#include "miscUtils.p4"
#include "forwardL2.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_STARFLOW_FULL 0x081A
#define ETHERTYPE_STARFLOW_SHORT 0x081B



#define SHORT_LEN      2

// Ensure that packet ID can be have SHORT_LEN once per evict.
#define TOTAL_LEN       8
#define TOTAL_LEN_M1    7
#define ROLLOVER_FLAG   100
#define TOTAL_LEN_M1_PROLLOVER_FLAG 107


#define SF_MC_GID 666
#define SF_MC_RECIRC_GID 667
#define SF_CLONE_MID 66
#define SF_COAL_MID  1016


#include "parser.p4"
#include "starFlow.p4"

control ingress {
	// Port to index mapping. Always do this.
    // if (ig_intr_md.resubmit_flag == 0){
    //     apply(tiPortToIndex);            
    // }
    // // Stage 0: apply L2 forwarding.
    // ciForwardPacket(); // (forwardL2.p4)
    // Next stages: apply TurboFlow (only to IPv4 packets)
    if (valid(ipv4)) {
	    ciStarFlow();
	}

}

control egress {  
	// Strip StarFlow headers unless its an eviction packet to the monitor port, or a recirculation packet.
	ceStarFlow();  
}



control ciStarFlow {

	// Stage 0: Setup Starflow headers.
	// apply(tiAddSfHeaders);



    // Stage 0: Update key fields and do preprocessing.
    // These tables only apply if ethertype == IPv4
    // tiUpdateSrcAddr sets inProcessing = 1.
    // tiUpdateSrcAddr also sets drop if its a recirc packet.
    apply(tiUpdateSrcAddr);
    apply(tiUpdateDstAddr);
    apply(tiUpdatePorts);
    apply(tiUpdateProtocol);

    // If packet is in processing, set match flag and increment packet counter.
    // Todo: also update start timestamp here.
    if (sfMeta.inProcessing == 1) {
        apply(tiSetMatch);
    }

    // If packet is in processing, apply stack alloc operations.
    if (sfMeta.inProcessing == 1) {
        // Stage 2, 3, 4: stack operations. (and more short vectors, optionally.)
        apply(tiDecrementStackTop); // Stage 2: stack top pointer.
        apply(tiUpdateStackArray); // Stage 3: read or write from stack, depending on stack top pointer.
        apply(tiUpdateWidePointerArray);// Stage 4: read or write from local extension pointer. 
    }
    // else, apply stack free operations.
    else {
        apply(tiIncrementStackTop);
        apply(tiFreeStackArray);                
    }

    // If packet is in processing, apply the vector ops and other stuff.
    if (sfMeta.inProcessing == 1) {
        // Stages 5 - 11: packet record ops.
        // short vector: 
        // - always read
        // - write if:
        //      1: widePtr == 0 and (pktId % SHORT_LEN == IDX)
        //      2: pktId == IDX
        // long vector: 
        // - always read
        // - write if: 
        //      1: pktId == IDX 
        //      * note: (widePtr == 0) --> write to garbage location
        apply(tiRWShortVec_0);
        apply(tiRWShortVec_1);
        apply(tiRWShortVec_2);
        apply(tiRWShortVec_3);

        apply(tiRWLongVec_0);
        apply(tiRWLongVec_1);
        apply(tiRWLongVec_2);
        apply(tiRWLongVec_3);
        apply(tiRWLongVec_4);
        apply(tiRWLongVec_5);
        apply(tiRWLongVec_6);
        apply(tiRWLongVec_7);
        apply(tiRWLongVec_8);
        apply(tiRWLongVec_9);
        apply(tiRWLongVec_10);
        apply(tiRWLongVec_11);
        apply(tiRWLongVec_12);
        apply(tiRWLongVec_13);
        apply(tiRWLongVec_14);
        apply(tiRWLongVec_15);
        apply(tiRWLongVec_16);
        apply(tiRWLongVec_17);
        apply(tiRWLongVec_18);
        apply(tiRWLongVec_19);
        apply(tiRWLongVec_20);
        apply(tiRWLongVec_21);
        apply(tiRWLongVec_22);
        apply(tiRWLongVec_23);
        
        // Correct key for export, in case some of the key fields match the new flow's fields.
        // (either a rollover or a new flow that partially matches the old flow.)
        
        apply(tiFixSrcAddr);
        apply(tiFixDstAddr);
        apply(tiFixPorts);
        apply(tiFixProtocol);

        // if (sfMeta.matchFlag == 0) {
        //     if (sfExportKey.srcAddr == 0) {
        //         apply(tiFixSrcAddr);
        //     }
        //     if (sfExportKey.dstAddr == 0) {
        //         apply(tiFixDstAddr);
        //     }
        //     if (sfExportKey.ports == 0) {
        //         apply(tiFixPorts);
        //     }
        //     if (sfExportKey.protocol == 0) {
        //         apply(tiFixProtocol);
        //     }
        // }

        // Export to CPU if evict or vectors are full.
        if (sfMeta.matchFlag == 0) {
            apply(tiEvictDecision);
        }
        else {
            apply(tiRolloverDecision);
        }
    }
}
