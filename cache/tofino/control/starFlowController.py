import os, inspect, json

if (os.environ['PROGNAME'] == ""):
    print("PROGNAME environment variable not set! Please run set_sde.bash")
    exit()
from switchThriftInterface import *


MASK32 = hex_to_i32(0xffffffff)


# reflect controller.
class StarFlowController(object):
    ETHERTYPE_STARFLOW_FULL = 0x081A
    ETHERTYPE_STARFLOW_SHORT = 0x081B

    SF_SHORT_TBL_SIZE = 1024
    SF_LONG_TBL_SIZE = 256

    SHORT_LEN = 2
    TOTAL_LEN = 8
    ROLLOVER_FLAG = 100

    SF_MC_GID = 666
    SF_MC_RECIRC_GID = 667

    def __init__(self, mgrObj, SIMULATION):

        if (SIMULATION) :
            self.SF_MONITOR_PORT = 3
            self.SF_RECIRC_PORT = 2
        else :
            self.SF_MONITOR_PORT = 144
            self.SF_RECIRC_PORT = 196

        self.mgrObj = mgrObj
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.entries = {}

        self.setupMcGroups()
        self.setupTables()
        self.initStack()
        self.initKeyTable()

    def setupMcGroups(self): 
        print("<starflow> setting up MC groups...")
        self.mcGroups = []
        # export to collection server.
        self.mcGroups.append(self.mgrObj.add_mc_group(self.SF_MC_GID, [self.SF_MONITOR_PORT]))
        # export to collection server and recirc for "free" op.
        self.mcGroups.append(self.mgrObj.add_mc_group(self.SF_MC_RECIRC_GID, [self.SF_RECIRC_PORT, self.SF_MONITOR_PORT]))

    def addExactMatch(self, tableName, matchParams, actionName, actionParams):
        """
        Add an exact match rule, insert record into self.entries for auto-cleanup at close.
        """
        if tableName not in self.entries:
            self.entries[tableName] = []
        print ("adding rule to table %s: (%s) --> %s(%s)"%(tableName, matchParams, actionName, actionParams))
        matchParams = ", ".join(["hex_to_i32("+str(p)+")" for p in matchParams])
        matchStr = "switch_"+tableName+"_match_spec_t("+matchParams+")"
        print "\t"+matchStr
        matchspec = eval(matchStr)
        if actionParams == []:
            addStr = "self.mgrObj.client.%s_table_add_with_%s(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, matchspec)"%(tableName, actionName)
            print "\t"+addStr
            result = eval(addStr)
            self.entries[tableName].append(result)
        else :
            actionParamsStr = ", ".join(["hex_to_i32("+str(p)+")" for p in actionParams])
            actionStr = "switch_"+actionName+"_action_spec_t("+actionParamsStr+")"
            actnspec = eval(actionStr)
            addStr = "self.mgrObj.client.%s_table_add_with_%s(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, matchspec, actnspec)"%(tableName, actionName)
            print "\t"+addStr
            result = eval(addStr)
            self.entries[tableName].append(result)

    def addTernaryMatch(self, tableName, matchParams, matchMasks, actionName, actionParams, priority):
        """
        Adds a ternary match. 
        matchParams: a list of the param values.
        matchMasks: a list of param masks. Bit value == 1 means "match on this bit". So 0xFF... is an exact match for the param, 0x00... is *
        priority: lower values are checked earlier. (i.e., priority=1 is checked first)
        """
        if tableName not in self.entries:
            self.entries[tableName] = []
        print ("adding rule to table %s: [priority: %s] (%s masks: %s) --> %s(%s)"%(tableName, priority, matchParams, matchMasks, actionName, actionParams))
        matchParamsStr = ""
        for (val, flag) in zip(matchParams, matchMasks):
            matchParamsStr += " hex_to_i32("+str(val)+"), hex_to_i32(" + str(flag) + "),"
        matchParamsStr = matchParamsStr[0:-1]
        # get match spec.
        matchStr = "switch_" + tableName+"_match_spec_t("+matchParamsStr+")"
        print "\t"+matchStr
        matchspec = eval(matchStr)
        # get action spec and add rule (with priority)
        if actionParams == []:
            addStr = "self.mgrObj.client.%s_table_add_with_%s(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, matchspec, priority)"%(tableName, actionName)
            print "\t"+addStr
            result = eval(addStr)
            self.entries[tableName].append(result)
        else :
            actionParamsStr = ", ".join(["hex_to_i32("+str(p)+")" for p in actionParams])
            actionStr = "switch_"+actionName+"_action_spec_t("+actionParamsStr+")"
            print actionStr
            actnspec = eval(actionStr)
            addStr = "self.mgrObj.client.%s_table_add_with_%s(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, matchspec, priority, actnspec)"%(tableName, actionName)
            print "\t"+addStr
            result = eval(addStr)
            self.entries[tableName].append(result)



    def setupTables(self):
        print("<starflow> setting up tables...")


        # update key.
        self.addExactMatch('tiUpdateSrcAddr', [0x0800], 'aiUpdateSrcAddr', [])
        self.addExactMatch('tiUpdateDstAddr', [0x0800], 'aiUpdateDstAddr', [])
        self.addExactMatch('tiUpdatePorts', [0x0800], 'aiUpdatePorts', [])
        self.addExactMatch('tiUpdateProtocol', [0x0800], 'aiUpdateProtocol', [])

        # drop recirc'd packets.
        self.addExactMatch('tiUpdateSrcAddr', [0x081A], 'aiDropRecircPkt', [])


        # set match.

        # (exportKey == 0) --> match.
        self.addTernaryMatch('tiSetMatch', [0, 0, 0, 0], [MASK32, MASK32, MASK32, MASK32], "aiSetMatch", [], 1)
        # (exportKey =! 0) --> no match.
        self.addTernaryMatch('tiSetMatch', [0, 0, 0, 0], [0,0,0,0], "aiSetNoMatch", [], 2)

        # stack ops.
        # pop from stack if packet id is exactly short_len
        self.addTernaryMatch("tiDecrementStackTop", [1, self.SHORT_LEN], [MASK32, MASK32], "aiPop", [], 1)
        # do nothing otherwise.
        self.addTernaryMatch("tiDecrementStackTop", [0,0], [0, 0], "aiNoOp", [], 2)

        # -- tiUpdateStackArray -- 
        # stackPtr = 0 --> stack alloc is not needed, or has failed.
        self.addTernaryMatch("tiUpdateStackArray", [0], [MASK32], "aiNoOp", [], 1)
        # stackPtr != 0 --> stack alloc successed.
        self.addTernaryMatch("tiUpdateStackArray", [0], [0], "aiStackRead", [], 2)

        # -- tiUpdateWidePointerArray --
        # pktId == shortLen --> set extension pointer (or lack thereof)
        self.addTernaryMatch("tiUpdateWidePointerArray", [self.SHORT_LEN], [MASK32], "aiSavePtr", [], 1)
        # pktId != shortLen --> load extension pointer. If its before save, it will not be used. After save, it will either be 0 or a valid value.
        self.addTernaryMatch("tiUpdateWidePointerArray", [0], [0], "aiLoadPtr", [], 2)

        # short vector tables.
        for i in range(0, self.SHORT_LEN):
            tableName = "tiRWShortVec_%s"%i
            rwActnName = "aiRWShortVec_%s"%i            
            rActnName = "aiRShortVec_%s"%i   
            # (widePtr == *, pktId == i) --> read and write
            self.addTernaryMatch(tableName, [0, i], [0, MASK32], rwActnName, [], 1)
            # (widePtr == *, pktId == i + ROLLOVER_FLAG) --> read and write
            self.addTernaryMatch(tableName, [0, i+self.ROLLOVER_FLAG], [0, MASK32], rwActnName, [], 1)

            # when there is no long buf, all the packet with IDs >= SHORT_LEN need to be written into the short buf.
            for j in range(self.SHORT_LEN, self.TOTAL_LEN):
                if (j % self.SHORT_LEN == i):
                    print ("pktId %s --> short %s"%(j, i))
                    # (widePtr == *, pktId % SHORT_LEN == i) --> read and write
                    self.addTernaryMatch(tableName, [0, j], [MASK32, MASK32], rwActnName, [], 2)
                    # (widePtr == *, pktId % SHORT_LEN == i + ROLLOVER_FLAG) --> read and write
                    self.addTernaryMatch(tableName, [0, j+self.ROLLOVER_FLAG], [MASK32, MASK32], rwActnName, [], 2)

            # any other scenario --> read only.
            self.addTernaryMatch(tableName, [0, 0], [0, 0], rActnName, [], 3)

            # (widePtr == 0, pktId == i % SHORT_LEN, )

        # long vector tables.
        for i in range(0, self.TOTAL_LEN - self.SHORT_LEN):
            tableName = "tiRWLongVec_%s"%i
            rwActnName = "aiRWLongVec_%s"%i            
            rActnName = "aiRLongVec_%s"%i   
            print ("table name: %s"%tableName)
            # pktId == (i + SHORT_LEN) --> RW
            self.addTernaryMatch(tableName, [i+self.SHORT_LEN], [MASK32], rwActnName, [], 1)
            # pktId == (i + SHORT_LEN + ROLLOVER) --> RW
            self.addTernaryMatch(tableName, [i+self.SHORT_LEN + self.ROLLOVER_FLAG], [MASK32], rwActnName, [], 1)
            # default: read only.
            self.addTernaryMatch(tableName, [0], [0], rActnName, [], 2)

        # # default: (exportKey == *) --> no match.
        # self.addTernaryMatch('tiSetMatch', [0, 0, 0, 0], [MASK32, MASK32, MASK32, MASK32], "aiSetMatch", [], 2)

        # evict decision table
        # widePtr == 0 --> short evict.
        # lastPktId can range from 1 to TOTAL_LEN-1. 
        # pktCt = (lastPktId % SHORT_LEN)
        # if lastPktId == 0, this is just clearing out an init flow, so do a no_op.
        self.addTernaryMatch("tiEvictDecision", [0, 0], [MASK32, MASK32], 'aiNoOp', [], 1)
        for j in range(1, self.TOTAL_LEN):
            if (j % self.SHORT_LEN) == 0:
                pktCt = self.SHORT_LEN
            else :
                pktCt = j % self.SHORT_LEN
            self.addTernaryMatch("tiEvictDecision", [0, j], [MASK32, MASK32], 'aiShortEvict', [pktCt], 1)

        # at lastPktID == ROLLOVER_FLAG, pktCt == TOTAL_LEN % SHORT_LEN
        # (because the evict happens at the exact time when a rollover would happen.)
        if (self.TOTAL_LEN % self.SHORT_LEN) == 0:
            pktCt = self.SHORT_LEN
        else:
            pktCt = self.TOTAL_LEN % self.SHORT_LEN
        self.addTernaryMatch("tiEvictDecision", [0, self.ROLLOVER_FLAG], [MASK32, MASK32], 'aiShortEvict', [pktCt], 1)

        # lastPktId can range from ROLLOVER_FLAG+1 to ROLLOVER_FLAG+TOTAL_LEN.
        # pktCt = (lastPktId - ROLLOVER_FLAG) % SHORT_LEN
        for j in range(self.ROLLOVER_FLAG+1, self.ROLLOVER_FLAG + self.TOTAL_LEN):
            if ((j-self.ROLLOVER_FLAG) % self.SHORT_LEN) == 0:
                pktCt = self.SHORT_LEN
            else :
                pktCt = (j-self.ROLLOVER_FLAG) % self.SHORT_LEN
            self.addTernaryMatch("tiEvictDecision", [0, j], [MASK32, MASK32], 'aiShortEvict', [pktCt], 1)

        # widePtr != 0 --> long evict
        # lastPktId can range from 1 to TOTAL_LEN-1
        # pktCt = lastPktId
        for j in range(1, self.TOTAL_LEN):
            self.addTernaryMatch("tiEvictDecision", [0, j], [0, MASK32], 'aiLongEvict', [j], 2)

        # at lastPktID == ROLLOVER_FLAG, pktCt == TOTAL_LEN
        # (because the evict happens at the exact time when a rollover would happen.)
        self.addTernaryMatch("tiEvictDecision", [0, self.ROLLOVER_FLAG], [0, MASK32], 'aiLongEvict', [self.TOTAL_LEN], 2)

        # lastPktId can range from ROLLOVER_FLAG+1 to ROLLOVER_FLAG+TOTAL_LEN.
        # pktCt = lastPktId-ROLLOVER_FLAG
        for j in range(self.ROLLOVER_FLAG+1, self.ROLLOVER_FLAG+self.TOTAL_LEN):
            self.addTernaryMatch("tiEvictDecision", [0, j], [0, MASK32], 'aiLongEvict', [j-self.ROLLOVER_FLAG], 2)

        # rollover decision table.
        # widePtr == 0 --> possible shortRollover.
        # pktId can range from 1 to TOTAL_LEN-1.
        # if pktId % SHORT_LEN == 0, the beginning of short vec was just overwritten and you need to export.
        for j in range(1, self.TOTAL_LEN):
            if (j % self.SHORT_LEN == 0):
                self.addTernaryMatch("tiRolloverDecision", [0, j], [MASK32, MASK32], "aiShortRollover", [], 1)
        # pktId can range from ROLLOVER_FLAG to ROLLOVER_FLAG + TOTAL_LEN -1.
        # if (pktId - ROLLOVER_FLAG) % SHORT_LEN == 0, the beginning of short vec was just overwritten and you need to export.
        for j in range(self.ROLLOVER_FLAG, self.ROLLOVER_FLAG+self.TOTAL_LEN):
            if ((j-self.ROLLOVER_FLAG) % self.SHORT_LEN == 0):
                self.addTernaryMatch("tiRolloverDecision", [0, j], [MASK32, MASK32], "aiShortRollover", [], 1)

        # widePtr != 0 --> possible longRollover.
        # pktId can range from 1 to TOTAL_LEN.
        # if pktId == ROLLOVER_FLAG, the beginning of the total vec was just overwritten and you need to export.
        self.addTernaryMatch("tiRolloverDecision", [0, self.ROLLOVER_FLAG], [0, MASK32], "aiLongRollover", [], 2)

        # default for rollover decision is noOp.        

        # egress table to leave the headers on packets to recirc or monitor.
        self.addExactMatch("teProcessSfHeader", [self.SF_MONITOR_PORT], "aeDoNothing", [])
        self.addExactMatch("teProcessSfHeader", [self.SF_RECIRC_PORT], "aeDoNothing", [])


        # fix key in case of export with partial match.
        self.addExactMatch("tiFixSrcAddr", [0], "aiFixSrcAddr", [])
        self.addExactMatch("tiFixDstAddr", [0], "aiFixDstAddr", [])
        self.addExactMatch("tiFixPorts", [0], "aiFixPorts", [])
        self.addExactMatch("tiFixProtocol", [0], "aiFixProtocol", [])

    def initStack(self):
        """
        Initialize the stack of pointers to free wide vectors. (registers)
        """
        # todo: fix thrift bug. Can riStack and riStackTop store 16 bit values, cast down to whatever size is needed? (probably, compiles ok)
        # 1. add every wide vector index to the stack.
        print ("initializing pointer stack.")
        for i in range(self.SF_LONG_TBL_SIZE):
            print ("setting riStack[%i] = %i"%(i, i))
            res = self.mgrObj.client.register_write_riStack(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, i, i)
            self.mgrObj.conn_mgr.complete_operations(self.mgrObj.sess_hdl)    
        print ("setting riStackTop[0] = %s"%(self.SF_LONG_TBL_SIZE-1))
        # 2. set the top of stack pointer to SF_LONG_TBL_SIZE-1
        res = self.mgrObj.client.register_write_riStackTop(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, 0, self.SF_LONG_TBL_SIZE-1)
        self.mgrObj.conn_mgr.complete_operations(self.mgrObj.sess_hdl)    

    def initKeyTable(self):
        """
        Initialize the key table so the first packet doesn't match.
        """
        for i in range(self.SF_SHORT_TBL_SIZE):
            res = self.mgrObj.client.register_write_rSrcAddr(self.mgrObj.sess_hdl, self.mgrObj.dev_tgt, i, 1)
            self.mgrObj.conn_mgr.complete_operations(self.mgrObj.sess_hdl)    


    def monitorLoop(self):
        # nothing to monitor for starflow.
        pass
        # flags = switch_register_flags_t(read_hw_sync=True)
        # while(1):
            # mgr = self.mgrObj
            # res = mgr.client.register_read_riFragmentedPkts(mgr.sess_hdl, mgr.dev_tgt, 0, flags)
            # mgr.conn_mgr.complete_operations(mgr.sess_hdl)    
            # fraggedPackets = max(res)
            # fragRate = fraggedPackets - lastFraggedPackets
            # lastFraggedPackets = fraggedPackets


    def cleanup(self):
        """
        delete everything that this module installed. (rules and mc groups)
        """
        for table in self.entries.keys():
            self.mgrObj.cleanup_table(table)
        for (mc_node_hdl, mc_grp_hdl) in self.mcGroups:
            # dissassociate.
            self.mgrObj.mc.mc_dissociate_node(self.mgrObj.mc_sess_hdl, self.mgrObj.dev_tgt.dev_id, hex_to_i32(mc_grp_hdl), hex_to_i32(mc_node_hdl))
            # destroy group.
            self.mgrObj.mc.mc_mgrp_destroy(self.mgrObj.mc_sess_hdl, self.mgrObj.dev_tgt.dev_id, hex_to_i32(mc_grp_hdl))
            # delete node.
            self.mgrObj.mc.mc_node_destroy(self.mgrObj.mc_sess_hdl, self.mgrObj.dev_tgt.dev_id, hex_to_i32(mc_node_hdl))
