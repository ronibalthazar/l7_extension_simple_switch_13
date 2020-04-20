from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, ofproto_v1_5
from ryu.lib.packet import ethernet, packet, tcp, ipv4, in_proto, ether_types
from ryu.utils import binary_str
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.topology import api
from glob import glob
from ast import literal_eval
import re
import hashlib
import configparser


FLOW_TIMEOUT = 300

class L7FirewallSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L7FirewallSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow = {}

        self.all_protocols = {}
        self.protocols = {}
        protocol = ''

        for file in glob('./patterns/*.pat'):
            lines = 0
            with open(file) as f:
                for line in f:
                    if line[0] != '#' and line.strip() != '':
                        lines += 1
                    if lines == 1:
                        protocol = line.strip()
                    elif lines == 2:
                        self.all_protocols[protocol] = re.compile(line.strip().encode('ascii'), re.I)
                        break

        config = configparser.ConfigParser()
        config.read('firewall.conf')

        [self.addPattern(i) for i in literal_eval(config.get("Patterns", "filteredPatterns"))]

        firewallPorts = config['Ports']

        self.logger.info("Firewall Filtered Ports: %s", firewallPorts['filteredPorts'])
        self.filteredPorts = literal_eval(firewallPorts['filteredPorts'])

        self.logger.info("Firewall Unfiltered Ports: %s", firewallPorts['unfilteredPorts'])
        self.unfilteredPorts = literal_eval(firewallPorts['unfilteredPorts'])

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
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # All flows are deleted
        self.delete_flow(datapath, ofproto.OFPTT_ALL, parser.OFPMatch())

        #Submit the msg again to table 99 / send the rule to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)] + [parser.OFPInstructionGotoTable(table_id=2)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=parser.OFPMatch(), instructions=inst, table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def datapath_change_handler(self, ev):
        if ev.enter: #new datapath registered to the controller
            datapath = ev.dp
            parser = datapath.ofproto_parser
            self.logger.info("New switch #%s joined", str(datapath.id))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id = 99, idle_timeout=FLOW_TIMEOUT):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if not actions: #drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else: #other kind of action
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, buffer_id=buffer_id,
                                    match=match, instructions=inst,
                                    table_id=table_id, idle_timeout=idle_timeout,
                                    command=ofproto.OFPFC_ADD, flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id, idle_timeout=idle_timeout,
                                    command=ofproto.OFPFC_ADD, flags=ofproto.OFPFF_SEND_FLOW_REM)

        datapath.send_msg(mod)

    def addPattern(self, protocol):
        if isinstance(protocol, list):
            for p in protocol:
                self.addPattern(p)
        else:
            if protocol in self.all_protocols.keys():
                self.protocols[protocol] = self.all_protocols[protocol]
                self.logger.info("Filtering protocol %s with the pattern %s", protocol, self.protocols[protocol].pattern )
            else:
                self.logger.info("Protocol [%s] is not supported. Consider adding a .pat file to the db", protocol)

    def delete_flow(self, dp, table_id, match):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = parser.OFPFlowMod(dp, 0, 0, table_id, ofp.OFPFC_DELETE, 0, 0, 1, ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match, [])
        dp.send_msg(flow_mod)
        return

    def getFlow(self, parser, in_port, eth_dst, eth_src, eth_type, ip_proto = 0, tcp_dst = 0):
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst, eth_src=eth_src, eth_type=eth_type)
        el = [str(in_port), '/', eth_src, "<>", eth_dst, ":", str(tcp_dst), ",", str(ip_proto)]
        flowID = hashlib.md5(''.join([c for c in el]).encode()).hexdigest()
        return match, flowID

    def matchChecker(self, currentPacket_payload):
        currentPacketBlocked = False
        for p in self.protocols.keys():
            self.logger.debug("*** Pattern Matched *** %s", self.protocols[p].match(currentPacket_payload))
            if self.protocols[p].match(currentPacket_payload) is not None:
                currentPacketBlocked = True
        return {'blocked' : currentPacketBlocked, 'protocol' : p}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #if ev.msg.msg_len < ev.msg.total_len:
        #    print("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        currentPacket = packet.Packet(msg.data)
        eth = currentPacket.get_protocols(ethernet.ethernet)[0]

        destination_tcp_port = 0
        source_tcp_port = 0
        packetAllowed = True
        blockReasons = []

        hasData = False
        protocols = [] #list of protocols encapsulated in the packet

        #list protocols inside packet and check if it has a payload
        for p in currentPacket.protocols:

            if not isinstance(p, (bytes, bytearray)):
                if p.protocol_name:
                    if p.protocol_name == 'ipv4':
                        ip_proto = p.proto
                    protocols.append(p.protocol_name)
            else: hasData = True

       	if 'tcp' in protocols: #packet has tcp
            currentPacket_tcp = currentPacket.get_protocol(tcp.tcp)
            #determine if it should be analyzed based on port numbers
            destination_tcp_port = currentPacket_tcp.dst_port
            source_tcp_port = currentPacket_tcp.src_port
            packetAllowed = (destination_tcp_port not in self.filteredPorts)
            if not packetAllowed:
                blockReasons.append('Filtered Port: ' + str(destination_tcp_port))

        packetAllowed = packetAllowed or (source_tcp_port in self.unfilteredPorts) or (destination_tcp_port in self.unfilteredPorts) or not hasData

        #if we got there, analyze the packet payload
        if packetAllowed and 'tcp' in protocols and hasData:
            matchChecker = self.matchChecker(currentPacket.protocols[-1])
            if matchChecker['blocked']:
                blockReasons.append('Pattern Not Allowed: ' + matchChecker['protocol'])
                packetAllowed = False

        #packet failed to be accepted, we install flows to block it

        if not packetAllowed:
            self.logger.info("Packet Blocked: %s *** Source/Destination Ports: %s --> %s *** Source/Destination MAC Addresses: %s --> %s",
                            ' / '.join(blockReasons), str(source_tcp_port),
                            str(destination_tcp_port), eth.src, eth.dst)

            #Rule to drop packets
            matchedBlock = parser.OFPMatch(in_port=in_port, eth_src=eth.src,
                                          eth_dst=eth.dst, eth_type=eth.ethertype,
                                          ip_proto=ip_proto, tcp_dst=destination_tcp_port)

            self.add_flow(datapath, 2, matchedBlock, None, None, 0, idle_timeout=FLOW_TIMEOUT)
            return

        if not packetAllowed:
            return

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
        self.logger.debug("Message out: %s", out)
        return

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                        'cookie=%d priority=%d reason=%s table_id=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'idle_timeout=%d hard_timeout=%d '
                        'packet_count=%d byte_count=%d match.fields=%s',
                        msg.cookie, msg.priority, reason, msg.table_id,
                        msg.duration_sec, msg.duration_nsec,
                        msg.idle_timeout, msg.hard_timeout,
                        msg.packet_count, msg.byte_count, msg.match)