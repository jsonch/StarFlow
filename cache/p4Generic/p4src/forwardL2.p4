/**
 *
 * forwardL2.p4 -- Simple layer 2 forwarding.
 * 
 */


/*==========================================
=          Data Plane Interface            =
==========================================*/

control ciForwardPacket {
	apply(tiL2Downstream) {
        aiMiss {
            apply(tiL2Upstream);
        }
    }
}

header_type L2Meta_t {
    fields {
        dstAddrMsb : 32;
    }
}
metadata L2Meta_t L2Meta;

/*====  End of Data Plane Interface  ======*/


/**
 *
 * Exact match forwarding to downstream based on ingress port and dest mac addr.
 *
 */
table tiL2Downstream {
    reads {
        globalMd.ingressPortId : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        aiUnicastEgress;
        aiMulticast;
        aiMiss;
    }
    default_action: aiMiss();
    size : 128;
}

/**
 *
 * default forwarding to upstream based on ingress port. Should only handle unicast.
 *
 */
table tiL2Upstream {
    reads {
        globalMd.ingressPortId : exact;        
    }
    actions {
        aiUnicastEgress;
    }
    size : 128;
}

// Unicast to a port.
action aiUnicastEgress(egressPort){
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egressPort);
}

// Multicast to a group.
action aiMulticast(mcGroup){
    modify_field(ig_intr_md_for_tm.mcast_grp_a, mcGroup);  
}
// Miss
action aiMiss() {}