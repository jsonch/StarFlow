
/**
 *
 * Mirroring for debug.
 *
 */
#define DBG_MIRROR_ID 91
field_list debugFl {
    globalMd.ingressPortId;
}


table tiFilteredMirrorToDebug {
    reads {ig_intr_md.ingress_port : exact;}
    actions {aiMirrorToSelectedDebug; aiNopPort; }
    default_action : aiNopPort();
}

table tiMirrorToDebug {
    actions {aiMirrorToDebug;}
    default_action : aiMirrorToDebug();
}
action aiMirrorToDebug() {
    clone_i2e(DBG_MIRROR_ID, debugFl);
}

action aiMirrorToSelectedDebug(mirId) {
    clone_i2e(mirId, debugFl);
}



/**
 *
 * Port to index table. Used by all applications. Should be packed into recirculate header and set before recirc.
 *
 */
header_type globalMd_t {
    fields {
        ingressPortId : 9;
    }
}
metadata globalMd_t globalMd;

table tiPortToIndex {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        aiPortToIndex; aiNopPort;
    }
    default_action : aiNopPort();
    size : 128;
}
action aiPortToIndex(portIndex) {
    modify_field(globalMd.ingressPortId, portIndex);
}
action aiNopPort() { no_op();}