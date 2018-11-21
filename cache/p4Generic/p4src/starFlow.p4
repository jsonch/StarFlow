/**
 *
 * starFlow.p4 -- StarFlow data plane.
 * 
 */
#include "statefulFunctions.p4"
// Max number of flows to track at once.
#define SF_SHORT_TBL_SIZE 32768
#define SF_SHORT_BIT_WIDTH 15 // log2(SF_SHORT_TBL_SIZE)

// Number of "wide" slots
#define SF_LONG_TBL_SIZE 8192
#define SF_LONG_PTR_WIDTH 13 // log2(SF_LONG_TBL_SIZE)


field_list flKeyFields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    l4_ports.ports;
    ipv4.protocol;
}

field_list_calculation flowKeyHashCalc {
    input { flKeyFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}

/*=========================================================
=            Update stateful keys, load evict FR.            =
=========================================================*/

field_list flFeatureFields {
    ipv4.totalLen;
}
field_list_calculation pktFeatureCalc {
    input {flFeatureFields;}
    algorithm : identity;
    output_width : 32;
}

@pragma stage 0
table tiUpdateSrcAddr {
    reads {ethernet.etherType : exact;}
    actions {aiUpdateSrcAddr; aiNoOp; aiDropRecircPkt;}
    default_action : aiNoOp();
    size : 128;
}
action aiUpdateSrcAddr() {  
    // Do all the setup and preprocessing in parallel.  
    add_header(sfExportStart);
    modify_field(sfExportStart.realEtherType, ethernet.etherType);
    modify_field(ethernet.etherType, ETHERTYPE_STARFLOW_FULL);

    // StarFlow data -- the exported flow's features.
    add_header(sfExportKey);
    // add both short and long headers. Remove long at end if its invalid.
    add_header(sfShortVector);
    add_header(sfLongVector);

    // Compute hash of key.
    modify_field_with_hash_based_offset(sfMeta.hashVal, 0, flowKeyHashCalc, 65536);
    // Get 32 bit timestamp. 
    modify_field(sfMeta.curTs, ig_intr_md.ingress_mac_tstamp);
    // modify_field(sfExportPacketVector.endTs, ig_intr_md.ingress_mac_tstamp);

    // Update source address.
    sUpdateSrcAddr();

    modify_field(sfMeta.inProcessing, 1);
}

action aiDropRecircPkt() {
    drop();
    // bypass_egress();
}

register rSrcAddr {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}

@pragma stage 0
@pragma ignore_table_dependency tiUpdateSrcAddr
table tiUpdateDstAddr {
    reads {ethernet.etherType : exact;}
    actions {aiUpdateDstAddr; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
action aiUpdateDstAddr() {
    // Set the packet feature vector. (Only timestamp right now.)
    // modify_field(currentPfVec.w0, ig_intr_md.ingress_mac_tstamp);
    modify_field_with_hash_based_offset(currentPfVec.w0, 0, pktFeatureCalc, 0x100000000);
    // modify_field(currentPfVec.w0, ipv4.totalLen);


    sUpdateDstAddr();
}


register rDstAddr {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}


@pragma stage 0
@pragma ignore_table_dependency tiUpdateDstAddr
@pragma ignore_table_dependency tiUpdateSrcAddr
table tiUpdatePorts {
    reads {ethernet.etherType : exact;}
    actions {aiUpdatePorts; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
action aiUpdatePorts() {
    sUpdatePorts();
}


register rPorts {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}


@pragma stage 0
@pragma ignore_table_dependency tiUpdatePorts
@pragma ignore_table_dependency tiUpdateDstAddr
@pragma ignore_table_dependency tiUpdateSrcAddr
table tiUpdateProtocol {
    reads {ethernet.etherType : exact;}
    actions {aiUpdateProtocol; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
action aiUpdateProtocol() {
    sUpdateProtocol();
}

register rProtocol {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}


/*=====  End of Update stateful keys, load evict FR.  ======*/


/*=======================================
=            Set evict flag.            =
=======================================*/

// (key == *) [default] --> no match.
// (key == 0) --> match.
@pragma stage 1
table tiSetMatch {
    reads {
        sfExportKey.srcAddr : ternary;
        sfExportKey.dstAddr : ternary;
        sfExportKey.ports : ternary;
        sfExportKey.protocol : ternary;
    }
    actions { aiSetNoMatch; aiSetMatch; }

    // default_action : aiSetNoMatch();
}
action aiSetMatch(){
    modify_field(sfMeta.matchFlag, 1);
    aiIncrementPktId();
}
action aiSetNoMatch(){
    modify_field(sfMeta.matchFlag, 0);
    aiResetPktId();
}

/*=====  End of Set evict flag.  ======*/




/*=======================================
=            Update Flow Features            =
=======================================*/

// Packet count.
action aiIncrementPktId() {
    sIncrementPktId();
}


action aiResetPktId() {
    sResetPktId();
    modify_field(sfMeta.pktId, 0);
}



register rNextPktId {
    width : 16;
    instance_count : SF_SHORT_TBL_SIZE;
}


// Start timestamp.
table tiResetStartTs {
    actions {aiResetStartTs;}
    default_action : aiResetStartTs();
}
action aiResetStartTs() {
    sResetStartTs();
}


register rStartTs {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}


// End timestamp -- no state needed, end Ts is just when the eviction happens.

/*=====  End of Update Flow Features  ======*/



/*=========================================
=            Stack operations.            =
=========================================*/

// ALLOC     :          (pktId == SHORT_LEN, matchFlag == 1) --> aiPop;
// OTHER / COLLISION:   (pktId == *,          matchFlag == *) --> aiNoOp;

@pragma stage 2
table tiDecrementStackTop {
    reads {
        // sfExportKey.srcAddr : ternary;
        // sfExportKey.dstAddr : ternary;
        // sfExportKey.ports : ternary;
        // sfExportKey.protocol : ternary;
        sfMeta.matchFlag : ternary;
        sfMeta.pktId : ternary;
    }
    actions {
        aiPop;
        aiNoOp;
    }
}

action aiPop() {
    siStackPop();
}


action aiNoOp() {
    no_op();
}

// After resubmit, complete the free op.
@pragma stage 2
table tiIncrementStackTop {
    actions {
        aiPush;
    }
    default_action : aiPush();
}

action aiPush() {
    modify_field(sfMeta.widePtr, sfExportStart.widePtr); // Prepare for next stage.
    siStackPush();
}


register riStackTop {
    width : 16;
    instance_count : 1;
}



// ALLOC NOT NEEDED OR FAIL:    (stackPtr == 0) --> no_op
// ALLOC SUCCESS:               (stackPtr == *) --> widePtr = riStack[stackPtr]
@pragma stage 3
table tiUpdateStackArray {
    reads {
        sfMeta.stackPtr : ternary;
    }
    actions { aiNoOp; aiStackRead; }
}

action aiStackRead() {
    siStackRead();
}


// FREE:                        --> riStack[stackPtr] = sfExportStart.widePtr
@pragma stage 3
table tiFreeStackArray {
    actions { aiStackWrite; }
    default_action : aiStackWrite();
}


action aiStackWrite() {
    siStackWrite();
}


register riStack {
    width : 16;
    instance_count : SF_LONG_TBL_SIZE;
}


// POST TRY ALLOC  :    (pktId == SHORT_LEN) --> riExtensionPtrs[hashVal] = widePtr;
// LOAD / COLLISION:    (pktId == *) --> widePtr = riExtensionPtrs[hashVal];
// COLLISION       :    (pktId == *) --> widePtr = riExtensionPtrs[hashVal]; 

table tiUpdateWidePointerArray {
    reads {
        sfMeta.pktId : ternary;
    }
    actions { aiSavePtr; aiLoadPtr; }
}

action aiSavePtr() {
    siSavePtr();
}

action aiLoadPtr() {
    siLoadPtr();
}


register riExtensionPtrs {
    width : SF_LONG_PTR_WIDTH;
    instance_count : SF_LONG_TBL_SIZE;
}



/*=====  End of Stack operations.  ======*/



/*===========================================
=            Update short vector            =
===========================================*/

// Only write if: 
// pktId == IDX
// widePtr == 0 and pktId % SHORT_LEN == IDX



// (pktId == IDX)                                   --> RW
// (pktId == IDX + 100)                             --> RW
// (widePtr == 0) && (pktId % SHORT_LEN     == IDX) --> RW
// (widePtr == 0) && (pktId % SHORT_LEN+100 == IDX) --> RW
// else -->                                             R

/*----------  shortVec[0]  ----------*/

table tiRWShortVec_0 {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.pktId : ternary;
    }
    actions {aiRShortVec_0; aiRWShortVec_0;}
}
// Read and write.
action aiRWShortVec_0() {
    sRWShortVec_0();
}

// Read only.
action aiRShortVec_0() {
    sRShortVec_0();
}

register rShortVec_0 {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}

/*----------  shortVec[1]  ----------*/


table tiRWShortVec_1 {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.pktId : ternary;
    }
    actions {aiRShortVec_1; aiRWShortVec_1;}
}
// Read and write.
action aiRWShortVec_1() {
    sRWShortVec_1();
}

// Read only.
action aiRShortVec_1() {
    sRShortVec_1();
}


register rShortVec_1 {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}



/*----------  shortVec[2]  ----------*/
table tiRWShortVec_2 {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.pktId : ternary;
    }
    actions {aiRShortVec_2; aiRWShortVec_2;}
}
// Read and write.
action aiRWShortVec_2() {
    sRWShortVec_2();
}


// Read only.
action aiRShortVec_2() {
    sRShortVec_2();
}

register rShortVec_2 {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}

/*----------  shortVec[3]  ----------*/
table tiRWShortVec_3 {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.pktId : ternary;
    }
    actions {aiRShortVec_3; aiRWShortVec_3;}
}
// Read and write.
action aiRWShortVec_3() {
    sRWShortVec_3();
}

// Read only.
action aiRShortVec_3() {
    sRShortVec_3();
}

register rShortVec_3 {
    width : 32;
    instance_count : SF_SHORT_TBL_SIZE;
}


/*=====  End of Update short vector  ======*/


/*==========================================
=            Update long vector            =
==========================================*/

// (pktId == IDX)                                   --> RW
// (pktId == IDX + 100)                             --> RW
// else -->                                             R

/*----------  longVec[0]  ----------*/
table tiRWLongVec_0 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_0; aiRWLongVec_0;}
}
action aiRWLongVec_0() {
    sRWLongVec_0();
}
action aiRLongVec_0() {
    sRLongVec_0();
}

register rLongVec_0 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[1]  ----------*/
table tiRWLongVec_1 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_1; aiRWLongVec_1;}
}
action aiRWLongVec_1() {
    sRWLongVec_1();
}
action aiRLongVec_1() {
    sRLongVec_1();
}

register rLongVec_1 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[2]  ----------*/
table tiRWLongVec_2 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_2; aiRWLongVec_2;}
}
action aiRWLongVec_2() {
    sRWLongVec_2();
}
action aiRLongVec_2() {
    sRLongVec_2();
}

register rLongVec_2 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[3]  ----------*/
table tiRWLongVec_3 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_3; aiRWLongVec_3;}
}
action aiRWLongVec_3() {
    sRWLongVec_3();
}
action aiRLongVec_3() {
    sRLongVec_3();
}

register rLongVec_3 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[4]  ----------*/
table tiRWLongVec_4 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_4; aiRWLongVec_4;}
}
action aiRWLongVec_4() {
    sRWLongVec_4();
}
action aiRLongVec_4() {
    sRLongVec_4();
}

register rLongVec_4 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[5]  ----------*/
table tiRWLongVec_5 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_5; aiRWLongVec_5;}
}
action aiRWLongVec_5() {
    sRWLongVec_5();
}
action aiRLongVec_5() {
    sRLongVec_5();
}

register rLongVec_5 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[6]  ----------*/
table tiRWLongVec_6 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_6; aiRWLongVec_6;}
}
action aiRWLongVec_6() {
    sRWLongVec_6();
}
action aiRLongVec_6() {
    sRLongVec_6();
}

register rLongVec_6 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[7]  ----------*/
table tiRWLongVec_7 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_7; aiRWLongVec_7;}
}
action aiRWLongVec_7() {
    sRWLongVec_7();
}
action aiRLongVec_7() {
    sRLongVec_7();
}

register rLongVec_7 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[8]  ----------*/
table tiRWLongVec_8 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_8; aiRWLongVec_8;}
}
action aiRWLongVec_8() {
    sRWLongVec_8();
}
action aiRLongVec_8() {
    sRLongVec_8();
}

register rLongVec_8 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[9]  ----------*/
table tiRWLongVec_9 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_9; aiRWLongVec_9;}
}
action aiRWLongVec_9() {
    sRWLongVec_9();
}
action aiRLongVec_9() {
    sRLongVec_9();
}

register rLongVec_9 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[10]  ----------*/
table tiRWLongVec_10 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_10; aiRWLongVec_10;}
}
action aiRWLongVec_10() {
    sRWLongVec_10();
}
action aiRLongVec_10() {
    sRLongVec_10();
}

register rLongVec_10 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[11]  ----------*/
table tiRWLongVec_11 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_11; aiRWLongVec_11;}
}
action aiRWLongVec_11() {
    sRWLongVec_11();
}
action aiRLongVec_11() {
    sRLongVec_11();
}

register rLongVec_11 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[12]  ----------*/
table tiRWLongVec_12 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_12; aiRWLongVec_12;}
}
action aiRWLongVec_12() {
    sRWLongVec_12();
}
action aiRLongVec_12() {
    sRLongVec_12();
}

register rLongVec_12 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[13]  ----------*/
table tiRWLongVec_13 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_13; aiRWLongVec_13;}
}
action aiRWLongVec_13() {
    sRWLongVec_13();
}
action aiRLongVec_13() {
    sRLongVec_13();
}

register rLongVec_13 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[14]  ----------*/
table tiRWLongVec_14 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_14; aiRWLongVec_14;}
}
action aiRWLongVec_14() {
    sRWLongVec_14();
}
action aiRLongVec_14() {
    sRLongVec_14();
}

register rLongVec_14 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[15]  ----------*/
table tiRWLongVec_15 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_15; aiRWLongVec_15;}
}
action aiRWLongVec_15() {
    sRWLongVec_15();
}
action aiRLongVec_15() {
    sRLongVec_15();
}

register rLongVec_15 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[16]  ----------*/
table tiRWLongVec_16 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_16; aiRWLongVec_16;}
}
action aiRWLongVec_16() {
    sRWLongVec_16();
}
action aiRLongVec_16() {
    sRLongVec_16();
}

register rLongVec_16 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[17]  ----------*/
table tiRWLongVec_17 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_17; aiRWLongVec_17;}
}
action aiRWLongVec_17() {
    sRWLongVec_17();
}
action aiRLongVec_17() {
    sRLongVec_17();
}

register rLongVec_17 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[18]  ----------*/
table tiRWLongVec_18 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_18; aiRWLongVec_18;}
}
action aiRWLongVec_18() {
    sRWLongVec_18();
}
action aiRLongVec_18() {
    sRLongVec_18();
}

register rLongVec_18 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[19]  ----------*/
table tiRWLongVec_19 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_19; aiRWLongVec_19;}
}
action aiRWLongVec_19() {
    sRWLongVec_19();
}
action aiRLongVec_19() {
    sRLongVec_19();
}

register rLongVec_19 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[20]  ----------*/
table tiRWLongVec_20 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_20; aiRWLongVec_20;}
}
action aiRWLongVec_20() {
    sRWLongVec_20();
}
action aiRLongVec_20() {
    sRLongVec_20();
}

register rLongVec_20 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[21]  ----------*/
table tiRWLongVec_21 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_21; aiRWLongVec_21;}
}
action aiRWLongVec_21() {
    sRWLongVec_21();
}
action aiRLongVec_21() {
    sRLongVec_21();
}

register rLongVec_21 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*----------  longVec[22]  ----------*/
table tiRWLongVec_22 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_22; aiRWLongVec_22;}
}
action aiRWLongVec_22() {
    sRWLongVec_22();
}
action aiRLongVec_22() {
    sRLongVec_22();
}

register rLongVec_22 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}



/*=====  End of Update long vector  ======*/



// An evict is definitely happening, because matchFlag == 0. 
// This table decides whether it is a short or long evict, and sets pktLen.
table tiEvictDecision {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.lastPktId : ternary; // this is actually the "next packet ID if flow was still active"
    }
    actions {
        aiShortEvict; aiLongEvict; aiNoOp;
    }
}

action aiShortEvict(actualPktCt) {
    // Change ethertype.
    modify_field(ethernet.etherType, ETHERTYPE_STARFLOW_SHORT);
    // Remove long header.
    remove_header(sfLongVector);
    // set pktCt = actualPktCt.
    modify_field(sfExportKey.pktCt, actualPktCt);
    // apply multicast.
    aiMcToCpu();
}

action aiLongEvict(actualPktCt) {
    // set pktCt = evictedPktId
    // modify_field(sfExportKey.pktCt, sfMeta.evictedPktId);
    // set metadata flags.
    modify_field(sfExportStart.widePtr, sfMeta.widePtr);
    // set pktCt = actualPktCt.
    modify_field(sfExportKey.pktCt, actualPktCt);
    // clone to the monitor and, to complete the "free" operation, the recirculation port.
    aiMcToCpuAndRecirc();
}

// There's no evict, but a rollover is required if:
// (widePtr == 0) and (pktId % SHORT_LEN == 0) <pktCt == SHORT_LEN> (or pktId + ROLLOVER_FLAG % SHORT_LEN == 0)
// (widePtr != 0) and (pktId == ROLLOVER_FLAG) <pktCt == TOTAL_LEN>

table tiRolloverDecision {
    reads {
        sfMeta.widePtr : ternary;
        sfMeta.pktId : ternary;
    }
    actions {
        aiShortRollover; aiLongRollover; aiNoOp;
    }
    default_action : aiNoOp();
}

action aiShortRollover() {
    // // Load key into export header.
    // aiLoadKey();
    // Change ethertype.
    modify_field(ethernet.etherType, ETHERTYPE_STARFLOW_SHORT);
    // Remove long header.
    remove_header(sfLongVector);
    // set pktCt = SHORT_LEN
    modify_field(sfExportKey.pktCt, SHORT_LEN);
    // apply multicast.
    aiMcToCpu();
}

action aiLongRollover() {
    // // Load key into export header.
    // aiLoadKey();
    // set pktCt = TOTAL_LEN
    modify_field(sfExportKey.pktCt, TOTAL_LEN);
    // apply multicast.
    aiMcToCpu();
}

action aiLoadKey() {
    modify_field(sfExportKey.srcAddr, ipv4.srcAddr);
    modify_field(sfExportKey.dstAddr, ipv4.dstAddr);
    modify_field(sfExportKey.ports, l4_ports.ports);
    modify_field(sfExportKey.protocol, ipv4.protocol);

}



action aiMcToCpu() {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, SF_MC_GID);  
}

action aiMcToCpuAndRecirc() {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, SF_MC_RECIRC_GID);  
}


/*=========================================
=            Adjust GPV header            =
=========================================*/


table tiFixSrcAddr {
    reads {sfExportKey.srcAddr : exact;}
    actions {aiFixSrcAddr; aiNoOp;}
    default_action : aiNoOp();
}
action aiFixSrcAddr() {
    modify_field(sfExportKey.srcAddr, ipv4.srcAddr);
}

table tiFixDstAddr {
    reads {sfExportKey.dstAddr : exact;}
    actions {aiFixDstAddr; aiNoOp;}
    default_action : aiNoOp();
}
action aiFixDstAddr() {
    modify_field(sfExportKey.dstAddr, ipv4.dstAddr);
}

table tiFixPorts {
    reads {sfExportKey.ports : exact;}
    actions {aiFixPorts; aiNoOp;}
    default_action :  aiNoOp();   
}
action aiFixPorts() {
    modify_field(sfExportKey.ports, l4_ports.ports);

}
table tiFixProtocol {
    reads {sfExportKey.protocol : exact;}
    actions {aiFixProtocol; aiNoOp;}
    default_action : aiNoOp();
}
action aiFixProtocol() {
    modify_field(sfExportKey.protocol, ipv4.protocol);
}

/*=====  End of Adjust GPV header  ======*/




/*==================================================
=            StarFlow Egress Pipeline.            =
==================================================*/

control ceStarFlow {
    if (valid(sfExportStart)) {
        apply(teProcessSfHeader);
    }
}


// default: (port == other) --> removeTfHeader()
// (port == monitorPort) --> do nothing.
// (port == recircPort) --> do nothing.
table teProcessSfHeader {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions { aeDoNothing; aeRemoveSfHeader;}
    default_action : aeRemoveSfHeader();
}

action aeDoNothing() {
    no_op();
}

action aeRemoveSfHeader() {
    modify_field(ethernet.etherType, sfExportStart.realEtherType);
    remove_header(sfExportStart);
    remove_header(sfExportKey);
    remove_header(sfShortVector);
    remove_header(sfLongVector);
}

// action aeCloneToTruncator() {
//     modify_field(sfMeta.isClone, 1);
//     clone_e2e(TF_CLONE_MID, flCloneMeta);
//     // sample_e2e(TF_COAL_MID, 72);
//     drop();
// }
// field_list flCloneMeta {
//     sfMeta.isClone;
// }

/*=====  End of StarFlow Egress Pipeline.  ======*/


