/**
 *
 * Headers, metadata, and parser.
 *
 */

// Max number of flows to track at once.
#define SF_SHORT_TBL_SIZE 8192
#define SF_SHORT_BIT_WIDTH 14 // log2(SF_SHORT_TBL_SIZE)

// Number of "wide" slots
#define SF_LONG_TBL_SIZE 4096
#define SF_LONG_PTR_WIDTH 13 // log2(SF_LONG_TBL_SIZE)



// Metadata for processing.
metadata sfMeta_t sfMeta;

// The current packet feature vector.
metadata currentPfVec_t currentPfVec;

// Headers for exporting an evicted flow record.
header sfExportStart_t sfExportStart;
header sfExportKey_t sfExportKey;
header sfShortVector_t sfShortVector;
header sfLongVector_t sfLongVector;

/*==========================================
=            StarFlow Headers.            =
==========================================*/

header_type currentPfVec_t {
    fields {
        w0 : 32;
    }
}


header_type sfMeta_t {
    fields {
        curTs : 32;
        pktId : 16; // Resets on evict.
        lastPktId : 16; // Filled when there is an evict.
        hashVal : SF_SHORT_BIT_WIDTH;
        matchFlag : 1;
        inProcessing : 1;
        stackPtr : SF_LONG_PTR_WIDTH; // Pointer to the top of the stack.
        widePtr : SF_LONG_PTR_WIDTH; // Loaded extension pointer.
    }
}

header_type sfExportStart_t {    
    fields {
        realEtherType : 16;
        widePtr : 16; // Loaded extension pointer.
    }
}

header_type sfExportKey_t {
    fields {
        srcAddr : 32;
        dstAddr : 32;
        ports : 32;
        startTs : 32;
        pktCt : 16;
        protocol : 8; 
    }
}


header_type sfShortVector_t {
    fields {
        w0 : 32;
        w1 : 32;
        w2 : 32;
        w3 : 32;
    }
}

header_type sfLongVector_t {
    fields {
        w0 : 32;
        w1 : 32;
        w2 : 32;
        w3 : 32;
        w4 : 32;
        w5 : 32;
        w6 : 32;
        w7 : 32;
        w8 : 32;
        w9 : 32;
        w10 : 32;
        w11 : 32;
        w12 : 32;
        w13 : 32;
        w14 : 32;
        w15 : 32;
        w16 : 32;
        w17 : 32;
        w18 : 32;
        w19 : 32;
        w20 : 32;
        w21 : 32;
        w22 : 32;
        w23 : 32;
    }
}



/*=====  End of StarFlow Headers.  ======*/

/*===========================================
=            Forwarding Headers.            =
===========================================*/

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16; // here
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;

header_type l4_ports_t {
    fields {
        ports : 32;
        // srcPort : 16;
        // dstPort : 16;
    }
}
header l4_ports_t l4_ports;


/*=====  End of Forwarding Headers.  ======*/




parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_STARFLOW_FULL   : parse_starflow_full; // This should never ingress or egress.
        ETHERTYPE_STARFLOW_SHORT  : parse_starflow_short;
        ETHERTYPE_IPV4 : parse_ipv4; 
        default : ingress;
    }
}

// IP.
parser parse_ipv4 {
    extract(ipv4);
    return parse_l4;
}

// TCP / UDP ports.
parser parse_l4 {
    extract(l4_ports);

    return ingress;
}

// Parse tree for in-processing packet with both short and long headers.
parser parse_starflow_full {
    extract(sfExportStart);
    extract(sfExportKey);
    extract(sfShortVector);
    extract(sfLongVector);
    return select(sfExportStart.realEtherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}

parser parse_starflow_short {
    extract(sfExportStart);
    extract(sfExportKey);
    extract(sfShortVector);
    return select(sfExportStart.realEtherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}

// Parse 

// // e2e mirrored is always (in this example) a ethernet TurboFlow packet.
// @pragma packet_entry
// parser start_e2e_mirrored {
//     extract(ethernet);
//     extract(sfExportStart);
//     extract(sfExportKey);
//     extract(sfExportPacketVector);
//     // set_metadata(tfMeta.isClone, 1);
//     return select(sfExportStart.realEtherType) {
//         ETHERTYPE_IPV4 : parse_ipv4;
//         default : ingress;
//     }
// }


// @pragma packet_entry
// parser start_coalesced {
//     // extract(ethernet);
//     set_metadata(tfMeta.isClone, 1);
//     return ingress;
// }