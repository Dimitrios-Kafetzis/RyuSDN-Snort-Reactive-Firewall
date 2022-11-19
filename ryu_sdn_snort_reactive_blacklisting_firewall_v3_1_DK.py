# Authors: Dimitrios Kafetzis and Nippon Telegraph and Telecom Company
#
# DISCLAIMER:
# This is a modified code of the initial simple_switch_snort.py that is 
# written by Nippon Telegraph and Telecom Corporation and is available
# on Ryu framework https://github.com/faucetsdn/ryu/tree/master/ryu/app
# 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# ----------------------------------------------------------------------
#
# This is a reactive firewall Ryu application that performs dynamically 
# black-listing and blocking of malicious traffic that is detected 
# by Snort IDS.
# 


from __future__ import print_function

import array


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
import ryufunc

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}
    
    #Initialization method, where the ryu-snort interface is established
    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        socket_config = {'unixsock': True}
        #Initialization of Snort's interconnection with Ryu controller
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        #Initialization of Black List that will include the IPv4 addresses 
        #of the detected as malicious nodes
        self.ipv4AddrBlackList=[]

    #This method prints on the terminal logs the input packets 
    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        
        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

    #This method is the Snort alerts' handler. 
    #When Snort IDS populates an Alert Event,
    #this is received by this handler. 
    #The reactive firewall is implemented in this method. 
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        #Print alert message received from Snort
        msg = ev.msg
        msg_tuple = msg.alertmsg
        result = f'alert msg: {msg_tuple}'
        print('alertmsg: %s' % ''.join(result))
        
        #The last received packet that rised the Snort alert is sent 
        #through the event message (ev.msg) 
        pkt = msg.pkt
        pkt = packet.Packet(array.array('B', pkt))
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        #The IPv4 addresses of the source (_ipv4.src) and destination (_ipv4.dst) nodes 
        #of the last received packet are organized as a tuple
        ipv4AddrTuple=(_ipv4.src,_ipv4.dst)
        #step 1: The IPv4 addresses tuple is checked 
        #if it is already included in the Black List
        if ipv4AddrTuple not in self.ipv4AddrBlackList:
            print("ipv4 address is not in list")
            #step 2: A new malicious node is detected in the network
            #and the tuple that includes its IPv4 address as a destination or as a source
            #address it is added in the Black List.
            print("Add it")
            self.ipv4AddrBlackList.append(ipv4AddrTuple)
            print("New Black List: ")
            print(self.ipv4AddrBlackList)
            print("Addition done!")
            
            #After the addition of the new malicious node's tuple
            #the firewall application must take an action for the mitigation of the
            #attack by establishing a new flow at the OvS switch's Flow Table.
            #step 3: The selection of the OvS switch of the network. In our case we have only one switch.
            DPID_list = ryufunc.get_switches()
            DPID = DPID_list[0]
            print("DPID list -->")
            print(DPID_list)
            #step 4: The definition of the new flow, where,
            #DPID:  A unique identifier for a switch so that someone/something 
            #       (e.g., an OpenFlow controller) can uniquely identify the switch
            #idle_timeout: The absolute timeout in which if there are no packets hitting 
            #              the flow for the duration, then flow is removed from the device.  
            #              (In this case will be 60 sec).
            #hard_timeout: The absolute timeout after which the flow is removed from the device.
            #              (In this case will be 60 sec).
            #priority: The matching precedence of the flow entry. The OpenFlow flow priority determines 
            #          the order of the terms in the filter, where higher priority terms are installed 
            #          above lower priority terms.
            #eth_type: The ethernet type filed indicates what kind of data the frame carries.
            #          In this matching filter, the value 0x0800 means that the frame has an IPv4 packet.
            #ip_proto: The protocol type of IP. It is an identifier for the encapsulated protocol and
            #          determines the layout of the data that immediately follows the header.
            #          For ICMP the value is "1", for TCP the value is "6" and for UDP the value is "17"
            #ipv4_src and ipv4_dst: the matched IPv4 addresses of the tuple that includes the malicious IP
            #**Actions are not defined in this flow rule because when we want to drop the packets 
            #which are match with this flow rule then we just do not define actions.
            flow_rule = {
                    "dpid": DPID,
                    "idle_timeout": 60, "hard_timeout": 60, "priority": 100,
                    "match": { "eth_type":"0x0800", "ip_proto":_ipv4.proto,
                               "ipv4_src":_ipv4.src, "ipv4_dst":_ipv4.dst },
                }
            #step 5: The addition of the new flow rule at the Flow Table of the OvS switch 
            #        (that has the specified DPID). 
            ryufunc.add_flow(flow_rule)
            self.logger.info("Block rule applied to SDN Controller.")
            print("Block rule applied to SDN Controller.")

        #For debugging reasons the packet is printed on the terminal.
        self.packet_print(msg.pkt)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
