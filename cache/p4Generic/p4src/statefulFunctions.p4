/**
 *
 * placeholders for stateful functions. 
 * These must be re implemented using platform specific logic.
 * (in BMV2, these should be custom primitives that extend the simple_switch target)
 *
 */

/*=============================================
=            Hash table functions.            =
=============================================*/



action sUpdateSrcAddr(){
	idx = flowKeyHashCalc();
	if (ipv4.srcAddr != rSrcAddr[idx]){
		sfExportKey.srcAddr = rSrcAddr[idx];
		rSrcAddr[idx]= ipv4.srcAddr;
	}
}

action sUpdateDstAddr(){
	idx = flowKeyHashCalc();
	if (ipv4.dstAddr != rDstAddr[idx]){
		sfExportKey.dstAddr = rDstAddr[idx];
		rDstAddr[idx] = ipv4.dstAddr;
	}
}

action sUpdatePorts(){
	idx = flowKeyHashCalc();
	if (l4_ports.ports != rPorts[idx]){
		sfExportKey.ports = rPorts[idx];
		rPorts[idx] = l4_ports.ports;
	}
}

action sUpdateProtocol(){
	idx = flowKeyHashCalc();
	if (ipv4.protocol != rProtocol[idx]){
		sfExportKey.protocol = rProtocol[idx];
		rProtocol[idx] = ipv4.protocol;
	}
}



/*=====  End of Hash table functions.  ======*/


/*==============================================
=            Flow Feature functions            =
==============================================*/


action sIncrementPktId(){
	idx = sfMeta.hashVal;
	if ((rNextPktId[idx] == TOTAL_LEN_M1) || (rNextPktId[idx] == TOTAL_LEN_M1_PROLLOVER_FLAG)){
		rNextPktId[idx] = ROLLOVER_FLAG;
	}
	if ! ((rNextPktId[idx] == TOTAL_LEN_M1) || (rNextPktId[idx] == TOTAL_LEN_M1_PROLLOVER_FLAG)){
		rNextPktId[idx] += 1;
	}
	sfMeta.pktId = rNextPktId[idx];
}

action sResetPktId(){
	idx = sfMeta.hashVal;
	rNextPktId[idx] = 1;
}

action sResetStartTs(){
	idx = sfMeta.hashVal;
	sfExportKey.startTs = rStartTs[idx];
	rStartTs[idx] = sfMeta.curTs;
}

/*=====  End of Flow Feature functions  ======*/


/*========================================
=            Stack operations            =
========================================*/

action siStackPop() {
	idx = 0;
	if (riStackTop[idx] != 0){
		sfMeta.stackPtr = riStackTop[idx];
		riStackTop[idx] = riStackTop[idx] - 1;
	}
}

action siStackPush(){
	idx = 0;
	riStackTop[idx] = riStackTop[idx] + 1;
	sfMeta.stackPtr = riStackTop[idx];
}

action siStackRead(){
	idx = sfMeta.stackPtr;
	sfMeta.widePtr = riStack[sfMeta.stackPtr];
}

action siStackWrite(){
	idx = sfMeta.stackPtr;
	riStack[idx] = sfMeta.widePtr;
}

action siSavePtr(){
	idx = sfMeta.hashVal;
	riExtensionPtrs[idx] = sfMeta.widePtr;
}

action siLoadPtr(){
	idx = sfMeta.hashVal;
	sfMeta.widePtr = riExtensionPtrs[idx];
	if (sfMeta.matchFlag == 0){
		riExtensionPtrs[idx] == 0;
	}
}

/*=====  End of Stack operations  ======*/

/*============================================
=            Update short vector.            =
============================================*/


action sRWShortVec_0() {
	idx = sfMeta.hashVal;
	sfShortVector.w0 = rShortVec_0[idx];
	rShortVec_0[idx] = currentPfVec.w0;
}
	

action sRShortVec_0() {
	idx = sfMeta.hashVal;
	sfShortVector.w0 = rShortVec_0[idx];
}
	

action sRWShortVec_1() {
	idx = sfMeta.hashVal;
	sfShortVector.w1 = rShortVec_1[idx];
	rShortVec_1[idx] = currentPfVec.w0;
}
	

action sRShortVec_1() {
	idx = sfMeta.hashVal;
	sfShortVector.w1 = rShortVec_1[idx];
}
	

action sRWShortVec_2() {
	idx = sfMeta.hashVal;
	sfShortVector.w2 = rShortVec_2[idx];
	rShortVec_2[idx] = currentPfVec.w0;
}
	

action sRShortVec_2() {
	idx = sfMeta.hashVal;
	sfShortVector.w2 = rShortVec_2[idx];
}
	

action sRWShortVec_3() {
	idx = sfMeta.hashVal;
	sfShortVector.w3 = rShortVec_3[idx];
	rShortVec_3[idx] = currentPfVec.w0;
}
	

action sRShortVec_3() {
	idx = sfMeta.hashVal;
	sfShortVector.w3 = rShortVec_3[idx];
}


/*=====  End of Update short vector.  ======*/


/*===========================================
=            Update long vector.            =
===========================================*/

action sRWLongVec_0() {
	idx = sfMeta.widePtr;
	sfLongVector.w0 = rLongVec_0[idx];
	rLongVec_0[idx] = currentPfVec.w0;
}
	

action sRLongVec_0() {
	idx = sfMeta.widePtr;
	sfLongVector.w0 = rLongVec_0[idx];
}
	

action sRWLongVec_1() {
	idx = sfMeta.widePtr;
	sfLongVector.w1 = rLongVec_1[idx];
	rLongVec_1[idx] = currentPfVec.w0;
}
	

action sRLongVec_1() {
	idx = sfMeta.widePtr;
	sfLongVector.w1 = rLongVec_1[idx];
}
	

action sRWLongVec_2() {
	idx = sfMeta.widePtr;
	sfLongVector.w2 = rLongVec_2[idx];
	rLongVec_2[idx] = currentPfVec.w0;
}
	

action sRLongVec_2() {
	idx = sfMeta.widePtr;
	sfLongVector.w2 = rLongVec_2[idx];
}
	

action sRWLongVec_3() {
	idx = sfMeta.widePtr;
	sfLongVector.w3 = rLongVec_3[idx];
	rLongVec_3[idx] = currentPfVec.w0;
}
	

action sRLongVec_3() {
	idx = sfMeta.widePtr;
	sfLongVector.w3 = rLongVec_3[idx];
}
	

action sRWLongVec_4() {
	idx = sfMeta.widePtr;
	sfLongVector.w4 = rLongVec_4[idx];
	rLongVec_4[idx] = currentPfVec.w0;
}
	

action sRLongVec_4() {
	idx = sfMeta.widePtr;
	sfLongVector.w4 = rLongVec_4[idx];
}
	

action sRWLongVec_5() {
	idx = sfMeta.widePtr;
	sfLongVector.w5 = rLongVec_5[idx];
	rLongVec_5[idx] = currentPfVec.w0;
}
	

action sRLongVec_5() {
	idx = sfMeta.widePtr;
	sfLongVector.w5 = rLongVec_5[idx];
}
	

action sRWLongVec_6() {
	idx = sfMeta.widePtr;
	sfLongVector.w6 = rLongVec_6[idx];
	rLongVec_6[idx] = currentPfVec.w0;
}
	

action sRLongVec_6() {
	idx = sfMeta.widePtr;
	sfLongVector.w6 = rLongVec_6[idx];
}
	

action sRWLongVec_7() {
	idx = sfMeta.widePtr;
	sfLongVector.w7 = rLongVec_7[idx];
	rLongVec_7[idx] = currentPfVec.w0;
}
	

action sRLongVec_7() {
	idx = sfMeta.widePtr;
	sfLongVector.w7 = rLongVec_7[idx];
}
	

action sRWLongVec_8() {
	idx = sfMeta.widePtr;
	sfLongVector.w8 = rLongVec_8[idx];
	rLongVec_8[idx] = currentPfVec.w0;
}
	

action sRLongVec_8() {
	idx = sfMeta.widePtr;
	sfLongVector.w8 = rLongVec_8[idx];
}
	

action sRWLongVec_9() {
	idx = sfMeta.widePtr;
	sfLongVector.w9 = rLongVec_9[idx];
	rLongVec_9[idx] = currentPfVec.w0;
}
	

action sRLongVec_9() {
	idx = sfMeta.widePtr;
	sfLongVector.w9 = rLongVec_9[idx];
}
	

action sRWLongVec_10() {
	idx = sfMeta.widePtr;
	sfLongVector.w10 = rLongVec_10[idx];
	rLongVec_10[idx] = currentPfVec.w0;
}
	

action sRLongVec_10() {
	idx = sfMeta.widePtr;
	sfLongVector.w10 = rLongVec_10[idx];
}
	

action sRWLongVec_11() {
	idx = sfMeta.widePtr;
	sfLongVector.w11 = rLongVec_11[idx];
	rLongVec_11[idx] = currentPfVec.w0;
}
	

action sRLongVec_11() {
	idx = sfMeta.widePtr;
	sfLongVector.w11 = rLongVec_11[idx];
}
	

action sRWLongVec_12() {
	idx = sfMeta.widePtr;
	sfLongVector.w12 = rLongVec_12[idx];
	rLongVec_12[idx] = currentPfVec.w0;
}
	

action sRLongVec_12() {
	idx = sfMeta.widePtr;
	sfLongVector.w12 = rLongVec_12[idx];
}
	

action sRWLongVec_13() {
	idx = sfMeta.widePtr;
	sfLongVector.w13 = rLongVec_13[idx];
	rLongVec_13[idx] = currentPfVec.w0;
}
	

action sRLongVec_13() {
	idx = sfMeta.widePtr;
	sfLongVector.w13 = rLongVec_13[idx];
}
	

action sRWLongVec_14() {
	idx = sfMeta.widePtr;
	sfLongVector.w14 = rLongVec_14[idx];
	rLongVec_14[idx] = currentPfVec.w0;
}
	

action sRLongVec_14() {
	idx = sfMeta.widePtr;
	sfLongVector.w14 = rLongVec_14[idx];
}
	

action sRWLongVec_15() {
	idx = sfMeta.widePtr;
	sfLongVector.w15 = rLongVec_15[idx];
	rLongVec_15[idx] = currentPfVec.w0;
}
	

action sRLongVec_15() {
	idx = sfMeta.widePtr;
	sfLongVector.w15 = rLongVec_15[idx];
}
	

action sRWLongVec_16() {
	idx = sfMeta.widePtr;
	sfLongVector.w16 = rLongVec_16[idx];
	rLongVec_16[idx] = currentPfVec.w0;
}
	

action sRLongVec_16() {
	idx = sfMeta.widePtr;
	sfLongVector.w16 = rLongVec_16[idx];
}
	

action sRWLongVec_17() {
	idx = sfMeta.widePtr;
	sfLongVector.w17 = rLongVec_17[idx];
	rLongVec_17[idx] = currentPfVec.w0;
}
	

action sRLongVec_17() {
	idx = sfMeta.widePtr;
	sfLongVector.w17 = rLongVec_17[idx];
}
	

action sRWLongVec_18() {
	idx = sfMeta.widePtr;
	sfLongVector.w18 = rLongVec_18[idx];
	rLongVec_18[idx] = currentPfVec.w0;
}
	

action sRLongVec_18() {
	idx = sfMeta.widePtr;
	sfLongVector.w18 = rLongVec_18[idx];
}
	

action sRWLongVec_19() {
	idx = sfMeta.widePtr;
	sfLongVector.w19 = rLongVec_19[idx];
	rLongVec_19[idx] = currentPfVec.w0;
}
	

action sRLongVec_19() {
	idx = sfMeta.widePtr;
	sfLongVector.w19 = rLongVec_19[idx];
}
	

action sRWLongVec_20() {
	idx = sfMeta.widePtr;
	sfLongVector.w20 = rLongVec_20[idx];
	rLongVec_20[idx] = currentPfVec.w0;
}
	

action sRLongVec_20() {
	idx = sfMeta.widePtr;
	sfLongVector.w20 = rLongVec_20[idx];
}
	

action sRWLongVec_21() {
	idx = sfMeta.widePtr;
	sfLongVector.w21 = rLongVec_21[idx];
	rLongVec_21[idx] = currentPfVec.w0;
}
	

action sRLongVec_21() {
	idx = sfMeta.widePtr;
	sfLongVector.w21 = rLongVec_21[idx];
}
	

action sRWLongVec_22() {
	idx = sfMeta.widePtr;
	sfLongVector.w22 = rLongVec_22[idx];
	rLongVec_22[idx] = currentPfVec.w0;
}
	

action sRLongVec_22() {
	idx = sfMeta.widePtr;
	sfLongVector.w22 = rLongVec_22[idx];
}


/*=====  End of Update long vector.  ======*/
