/**
 *
 * starFlow.p4 -- StarFlow data plane.
 * 
 */

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
    sUpdateSrcAddr.execute_stateful_alu_from_hash(flowKeyHashCalc);
    // sUpdateSrcAddr.execute_stateful_alu(sfMeta.hashVal);

    modify_field(sfMeta.inProcessing, 1);
}

action aiDropRecircPkt() {
    drop();
    // bypass_egress();
}


// evictFr.srcAddr = entry
// If new != entry:
//      entry = new.srcAddr
blackbox stateful_alu sUpdateSrcAddr {
    reg : rSrcAddr;
    condition_lo : ipv4.srcAddr == register_lo;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : ipv4.srcAddr;

    output_predicate : not condition_lo;
    output_dst : sfExportKey.srcAddr;
    output_value : register_lo;
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


    sUpdateDstAddr.execute_stateful_alu_from_hash(flowKeyHashCalc);
    // sUpdateDstAddr.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sUpdateDstAddr {
    reg : rDstAddr;
    condition_lo : ipv4.dstAddr == register_lo;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : ipv4.dstAddr;

    output_predicate : not condition_lo;
    output_dst : sfExportKey.dstAddr;
    output_value : register_lo;
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
    sUpdatePorts.execute_stateful_alu_from_hash(flowKeyHashCalc);
    // sUpdatePorts.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sUpdatePorts {
    reg : rPorts;
    condition_lo : l4_ports.ports == register_lo;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : l4_ports.ports;

    output_predicate : not condition_lo;
    output_dst : sfExportKey.ports;
    output_value : register_lo;
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
    sUpdateProtocol.execute_stateful_alu_from_hash(flowKeyHashCalc);
    // sUpdateProtocol.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sUpdateProtocol {
    reg : rProtocol;
    condition_lo : ipv4.protocol == register_lo;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : ipv4.protocol;

    output_predicate : not condition_lo;
    output_dst : sfExportKey.protocol;
    output_value : register_lo;
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
    sIncrementPktId.execute_stateful_alu(sfMeta.hashVal);
}
// Return current ID. Rollover at TOTAL_LEN, with +100 as flag indicating at least 1 rollover. 
blackbox stateful_alu sIncrementPktId {
    reg : rNextPktId;
    condition_lo : register_lo == TOTAL_LEN_M1;
    condition_hi : register_lo == TOTAL_LEN_M1_PROLLOVER_FLAG;
    update_lo_2_predicate : condition_lo or condition_hi;
    update_lo_2_value : ROLLOVER_FLAG;

    update_lo_1_predicate : not (condition_lo or condition_hi);
    update_lo_1_value : register_lo + 1;


    output_dst : sfMeta.pktId;
    output_value : register_lo;
}

action aiResetPktId() {
    sResetPktId.execute_stateful_alu(sfMeta.hashVal);
    modify_field(sfMeta.pktId, 0);
}

// Reads the last "next packet id"
// Sets packetID = 1 for the next packet in the flow. 
// The current packet is packetId = 0, set by outer action.
blackbox stateful_alu sResetPktId {
    reg : rNextPktId;
    update_lo_1_value : 1;
    output_dst : sfMeta.lastPktId;
    output_value : register_lo;
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
    sResetStartTs.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sResetStartTs {
    reg : rStartTs;
    update_lo_1_value : sfMeta.curTs;
    output_dst : sfExportKey.startTs;
    output_value : register_lo;
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
    siStackPop.execute_stateful_alu(0);
}

// Return and decrement stack top pointer if not at 0.
blackbox stateful_alu siStackPop {
    reg : riStackTop;
    condition_lo : register_lo == 0;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : register_lo - 1;

    output_predicate : not condition_lo;
    output_dst : sfMeta.stackPtr;
    output_value : register_lo;
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
    siStackPush.execute_stateful_alu(0);
}

// Increment stack top ptr, which will now store a free slot.
blackbox stateful_alu siStackPush {
    reg : riStackTop;
    update_lo_1_value : register_lo + 1;
    output_dst : sfMeta.stackPtr;
    output_value : alu_lo;
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
    siStackRead.execute_stateful_alu(sfMeta.stackPtr);
}

blackbox stateful_alu siStackRead {
    reg : riStack;
    output_dst : sfMeta.widePtr;
    output_value : register_lo;
}


// FREE:                        --> riStack[stackPtr] = sfExportStart.widePtr
@pragma stage 3
table tiFreeStackArray {
    actions { aiStackWrite; }
    default_action : aiStackWrite();
}


action aiStackWrite() {
    siStackWrite.execute_stateful_alu(sfMeta.stackPtr);
}

blackbox stateful_alu siStackWrite {
    reg : riStack;
    update_lo_1_value : sfMeta.widePtr;
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
    siSavePtr.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu siSavePtr {
    reg : riExtensionPtrs;
    update_lo_1_value : sfMeta.widePtr;
}

action aiLoadPtr() {
    siLoadPtr.execute_stateful_alu(sfMeta.hashVal);
}
blackbox stateful_alu siLoadPtr {
    reg : riExtensionPtrs;
    // If this is a long evict, reset the long pointer to 0.
    // Else, a subsequent short evict will be incorrect.
    condition_lo : sfMeta.matchFlag == 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : 0;

    output_dst :  sfMeta.widePtr;
    output_value : register_lo;
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
    sRWShortVec_0.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRWShortVec_0 {
    reg : rShortVec_0;
    output_dst : sfShortVector.w0;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRShortVec_0() {
    sRShortVec_0.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRShortVec_0 {
    reg : rShortVec_0;
    output_dst : sfShortVector.w0;
    output_value : register_lo;
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
    sRWShortVec_1.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRWShortVec_1 {
    reg : rShortVec_1;
    output_dst : sfShortVector.w1;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRShortVec_1() {
    sRShortVec_1.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRShortVec_1 {
    reg : rShortVec_1;
    output_dst : sfShortVector.w1;
    output_value : register_lo;
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
    sRWShortVec_2.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRWShortVec_2 {
    reg : rShortVec_2;
    output_dst : sfShortVector.w2;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRShortVec_2() {
    sRShortVec_2.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRShortVec_2 {
    reg : rShortVec_2;
    output_dst : sfShortVector.w2;
    output_value : register_lo;
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
    sRWShortVec_3.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRWShortVec_3 {
    reg : rShortVec_3;
    output_dst : sfShortVector.w3;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRShortVec_3() {
    sRShortVec_3.execute_stateful_alu(sfMeta.hashVal);
}

blackbox stateful_alu sRShortVec_3 {
    reg : rShortVec_3;
    output_dst : sfShortVector.w3;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_0() {
    sRWLongVec_0.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_0 {
    reg : rLongVec_0;
    output_dst : sfLongVector.w0;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_0() {
    sRLongVec_0.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_0 {
    reg : rLongVec_0;
    output_dst : sfLongVector.w0;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_1() {
    sRWLongVec_1.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_1 {
    reg : rLongVec_1;
    output_dst : sfLongVector.w1;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_1() {
    sRLongVec_1.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_1 {
    reg : rLongVec_1;
    output_dst : sfLongVector.w1;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_2() {
    sRWLongVec_2.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_2 {
    reg : rLongVec_2;
    output_dst : sfLongVector.w2;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_2() {
    sRLongVec_2.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_2 {
    reg : rLongVec_2;
    output_dst : sfLongVector.w2;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_3() {
    sRWLongVec_3.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_3 {
    reg : rLongVec_3;
    output_dst : sfLongVector.w3;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_3() {
    sRLongVec_3.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_3 {
    reg : rLongVec_3;
    output_dst : sfLongVector.w3;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_4() {
    sRWLongVec_4.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_4 {
    reg : rLongVec_4;
    output_dst : sfLongVector.w4;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_4() {
    sRLongVec_4.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_4 {
    reg : rLongVec_4;
    output_dst : sfLongVector.w4;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_5() {
    sRWLongVec_5.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_5 {
    reg : rLongVec_5;
    output_dst : sfLongVector.w5;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_5() {
    sRLongVec_5.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_5 {
    reg : rLongVec_5;
    output_dst : sfLongVector.w5;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_6() {
    sRWLongVec_6.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_6 {
    reg : rLongVec_6;
    output_dst : sfLongVector.w6;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_6() {
    sRLongVec_6.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_6 {
    reg : rLongVec_6;
    output_dst : sfLongVector.w6;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_7() {
    sRWLongVec_7.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_7 {
    reg : rLongVec_7;
    output_dst : sfLongVector.w7;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_7() {
    sRLongVec_7.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_7 {
    reg : rLongVec_7;
    output_dst : sfLongVector.w7;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_8() {
    sRWLongVec_8.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_8 {
    reg : rLongVec_8;
    output_dst : sfLongVector.w8;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_8() {
    sRLongVec_8.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_8 {
    reg : rLongVec_8;
    output_dst : sfLongVector.w8;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_9() {
    sRWLongVec_9.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_9 {
    reg : rLongVec_9;
    output_dst : sfLongVector.w9;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_9() {
    sRLongVec_9.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_9 {
    reg : rLongVec_9;
    output_dst : sfLongVector.w9;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_10() {
    sRWLongVec_10.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_10 {
    reg : rLongVec_10;
    output_dst : sfLongVector.w10;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_10() {
    sRLongVec_10.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_10 {
    reg : rLongVec_10;
    output_dst : sfLongVector.w10;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_11() {
    sRWLongVec_11.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_11 {
    reg : rLongVec_11;
    output_dst : sfLongVector.w11;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_11() {
    sRLongVec_11.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_11 {
    reg : rLongVec_11;
    output_dst : sfLongVector.w11;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_12() {
    sRWLongVec_12.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_12 {
    reg : rLongVec_12;
    output_dst : sfLongVector.w12;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_12() {
    sRLongVec_12.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_12 {
    reg : rLongVec_12;
    output_dst : sfLongVector.w12;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_13() {
    sRWLongVec_13.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_13 {
    reg : rLongVec_13;
    output_dst : sfLongVector.w13;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_13() {
    sRLongVec_13.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_13 {
    reg : rLongVec_13;
    output_dst : sfLongVector.w13;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_14() {
    sRWLongVec_14.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_14 {
    reg : rLongVec_14;
    output_dst : sfLongVector.w14;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_14() {
    sRLongVec_14.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_14 {
    reg : rLongVec_14;
    output_dst : sfLongVector.w14;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_15() {
    sRWLongVec_15.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_15 {
    reg : rLongVec_15;
    output_dst : sfLongVector.w15;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_15() {
    sRLongVec_15.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_15 {
    reg : rLongVec_15;
    output_dst : sfLongVector.w15;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_16() {
    sRWLongVec_16.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_16 {
    reg : rLongVec_16;
    output_dst : sfLongVector.w16;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_16() {
    sRLongVec_16.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_16 {
    reg : rLongVec_16;
    output_dst : sfLongVector.w16;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_17() {
    sRWLongVec_17.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_17 {
    reg : rLongVec_17;
    output_dst : sfLongVector.w17;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_17() {
    sRLongVec_17.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_17 {
    reg : rLongVec_17;
    output_dst : sfLongVector.w17;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_18() {
    sRWLongVec_18.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_18 {
    reg : rLongVec_18;
    output_dst : sfLongVector.w18;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_18() {
    sRLongVec_18.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_18 {
    reg : rLongVec_18;
    output_dst : sfLongVector.w18;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_19() {
    sRWLongVec_19.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_19 {
    reg : rLongVec_19;
    output_dst : sfLongVector.w19;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_19() {
    sRLongVec_19.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_19 {
    reg : rLongVec_19;
    output_dst : sfLongVector.w19;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_20() {
    sRWLongVec_20.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_20 {
    reg : rLongVec_20;
    output_dst : sfLongVector.w20;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_20() {
    sRLongVec_20.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_20 {
    reg : rLongVec_20;
    output_dst : sfLongVector.w20;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_21() {
    sRWLongVec_21.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_21 {
    reg : rLongVec_21;
    output_dst : sfLongVector.w21;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_21() {
    sRLongVec_21.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_21 {
    reg : rLongVec_21;
    output_dst : sfLongVector.w21;
    output_value : register_lo;
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
// Read and write.
action aiRWLongVec_22() {
    sRWLongVec_22.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_22 {
    reg : rLongVec_22;
    output_dst : sfLongVector.w22;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_22() {
    sRLongVec_22.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_22 {
    reg : rLongVec_22;
    output_dst : sfLongVector.w22;
    output_value : register_lo;
}

register rLongVec_22 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}
/*----------  longVec[23]  ----------*/
table tiRWLongVec_23 {
    reads {
        sfMeta.pktId : ternary;
    }
    actions {aiRLongVec_23; aiRWLongVec_23;}
}
// Read and write.
action aiRWLongVec_23() {
    sRWLongVec_23.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRWLongVec_23 {
    reg : rLongVec_23;
    output_dst : sfLongVector.w23;
    output_value : register_lo;
    update_lo_1_value : currentPfVec.w0;
}

// Read only.
action aiRLongVec_23() {
    sRLongVec_23.execute_stateful_alu(sfMeta.widePtr);
}

blackbox stateful_alu sRLongVec_23 {
    reg : rLongVec_23;
    output_dst : sfLongVector.w23;
    output_value : register_lo;
}

register rLongVec_23 {
    width : 32;
    instance_count : SF_LONG_TBL_SIZE;
}


// /*----------  longVec[0]  ----------*/
// table tiRWLongVec_0 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_0; aiRWLongVec_0;}
// }
// // Read and write.
// action aiRWLongVec_0() {
//     sRWLongVec_0.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_0 {
//     reg : rLongVec_0;
//     output_dst : sfLongVector.w0;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_0() {
//     sRLongVec_0.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_0 {
//     reg : rLongVec_0;
//     output_dst : sfLongVector.w0;
//     output_value : register_lo;
// }

// register rLongVec_0 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }

// /*----------  longVec[1] ----------*/
// table tiRWLongVec_1 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_1; aiRWLongVec_1;}
// }
// // Read and write.
// action aiRWLongVec_1() {
//     sRWLongVec_1.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_1 {
//     reg : rLongVec_1;
//     output_dst : sfLongVector.w1;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_1() {
//     sRLongVec_1.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_1 {
//     reg : rLongVec_1;
//     output_dst : sfLongVector.w1;
//     output_value : register_lo;
// }

// register rLongVec_1 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }

// /*----------  longVec[2] ----------*/
// table tiRWLongVec_2 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_2; aiRWLongVec_2;}
// }
// // Read and write.
// action aiRWLongVec_2() {
//     sRWLongVec_2.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_2 {
//     reg : rLongVec_2;
//     output_dst : sfLongVector.w2;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_2() {
//     sRLongVec_2.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_2 {
//     reg : rLongVec_2;
//     output_dst : sfLongVector.w2;
//     output_value : register_lo;
// }

// register rLongVec_2 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }

// /*----------  longVec[3] ----------*/
// table tiRWLongVec_3 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_3; aiRWLongVec_3;}
// }
// // Read and write.
// action aiRWLongVec_3() {
//     sRWLongVec_3.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_3 {
//     reg : rLongVec_3;
//     output_dst : sfLongVector.w3;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_3() {
//     sRLongVec_3.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_3 {
//     reg : rLongVec_3;
//     output_dst : sfLongVector.w3;
//     output_value : register_lo;
// }

// register rLongVec_3 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }

// /*----------  longVec[4] ----------*/
// table tiRWLongVec_4 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_4; aiRWLongVec_4;}
// }
// // Read and write.
// action aiRWLongVec_4() {
//     sRWLongVec_4.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_4 {
//     reg : rLongVec_4;
//     output_dst : sfLongVector.w4;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_4() {
//     sRLongVec_4.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_4 {
//     reg : rLongVec_4;
//     output_dst : sfLongVector.w4;
//     output_value : register_lo;
// }

// register rLongVec_4 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }

// /*----------  longVec[5] ----------*/
// table tiRWLongVec_5 {
//     reads {
//         sfMeta.pktId : ternary;
//     }
//     actions {aiRLongVec_5; aiRWLongVec_5;}
// }
// // Read and write.
// action aiRWLongVec_5() {
//     sRWLongVec_5.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRWLongVec_5 {
//     reg : rLongVec_5;
//     output_dst : sfLongVector.w5;
//     output_value : register_lo;
//     update_lo_1_value : currentPfVec.w0;
// }

// // Read only.
// action aiRLongVec_5() {
//     sRLongVec_5.execute_stateful_alu(sfMeta.widePtr);
// }

// blackbox stateful_alu sRLongVec_5 {
//     reg : rLongVec_5;
//     output_dst : sfLongVector.w5;
//     output_value : register_lo;
// }

// register rLongVec_5 {
//     width : 32;
//     instance_count : SF_LONG_TBL_SIZE;
// }



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


