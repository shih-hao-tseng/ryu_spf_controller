#
# Simple Shortest Path First Controller in Ryu
# Copyright (C) 2020  Shih-Hao Tseng <shtseng@caltech.edu>
# 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# references/sources:
# http://csie.nqu.edu.tw/smallko/sdn/ryu_sp13.htm
# http://106.15.204.80/2017/05/18/RYU%E5%A4%84%E7%90%86ARP%E5%8D%8F%E8%AE%AE/

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, arp, ether_types
 
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
 
class SPFController(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
	def __init__(self, *args, **kwargs):
		super(SPFController, self).__init__(*args, **kwargs)
		self.topology_api_app = self
		self.net=nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0
		self.i=0
		self.arp_table = {}
		self.ip_to_datapath = {}
		self.dpid_to_datapath = {}
  
	def add_flow(self, datapath, dst, out_port):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser	  
		match = datapath.ofproto_parser.OFPMatch(eth_dst=dst)
		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
		mod = datapath.ofproto_parser.OFPFlowMod(
			datapath=datapath, match=match, cookie=0,
			command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
			priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
		datapath.send_msg(mod)
 
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
	def switch_features_handler(self , ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]
		mod = datapath.ofproto_parser.OFPFlowMod(
			datapath=datapath, match=match, cookie=0,
			command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
		datapath.send_msg(mod)
 
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth_hdr = pkt.get_protocol(ethernet.ethernet)

		if not eth_hdr:
			return
		
		# filters out LLDP
		if eth_hdr.ethertype == 0x88cc:
			return

		datapath = msg.datapath
		dpid	= datapath.id
		ofproto = datapath.ofproto
		parser  = datapath.ofproto_parser
		in_port = msg.match['in_port']

		dst = eth_hdr.dst
		src = eth_hdr.src

		# for routing 
		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid,src,port=in_port)
			self.net.add_edge(src,dpid)

		# ARP
		if eth_hdr.ethertype == 0x0806:
			self.arp_handler (
				pkt=pkt,
				src=src,
				dst=dst,
				datapath=datapath,
				dpid=dpid,
				ofproto=ofproto,
				parser=parser,
				in_port=in_port
			)
			return

		# IPv4 routing
		if eth_hdr.ethertype == 0x0800:
			self.ipv4_routing (
				msg=msg,
				src=src,
				dst=dst,
				datapath=datapath,
				dpid=dpid,
				ofproto=ofproto,
				parser=parser,
				in_port=in_port
			)
			return

	def arp_handler(self,pkt,src,dst,datapath,dpid,ofproto,parser,in_port):
		arp_hdr = pkt.get_protocol(arp.arp)
		if not arp_hdr:
			return

		arp_src_ip = arp_hdr.src_ip
		arp_dst_ip = arp_hdr.dst_ip
		eth_src = src
		eth_dst = dst

		self.arp_table[arp_src_ip] = eth_src
		self.ip_to_datapath[arp_src_ip] = datapath

		# print " ARP: %s (%s) -> %s (%s)" % (arp_src_ip, src, arp_dst_ip, dst)

		hwtype = arp_hdr.hwtype
		proto = arp_hdr.proto
		hlen = arp_hdr.hlen
		plen = arp_hdr.plen

		if arp_hdr.opcode == arp.ARP_REQUEST:
			# request
			# lookup the arp_table
			if arp_dst_ip in self.arp_table:
				actions = [parser.OFPActionOutput(in_port)]
				ARP_Reply = packet.Packet()
				eth_dst = self.arp_table[arp_dst_ip]
				# reply
				ARP_Reply.add_protocol(ethernet.ethernet(
					ethertype=0x0806,
					dst=eth_src,
					src=eth_dst))
				ARP_Reply.add_protocol(arp.arp(
					opcode=arp.ARP_REPLY,
					src_mac=eth_dst,
					src_ip=arp_dst_ip,
					dst_mac=eth_src,
					dst_ip=arp_src_ip))

				ARP_Reply.serialize()
				# send back
				out = parser.OFPPacketOut(
					datapath=datapath,
					buffer_id=ofproto.OFP_NO_BUFFER,
					in_port=ofproto.OFPP_CONTROLLER,
					actions=actions, data=ARP_Reply.data)
				datapath.send_msg(out)
				return True
			else:
				# need to ask the nodes
				for sw_datapath in self.dpid_to_datapath.values():
					if sw_datapath == datapath:
						continue
					actions = [parser.OFPActionOutput(in_port)]
					out = parser.OFPPacketOut(
						datapath=sw_datapath,
						buffer_id=ofproto.OFP_NO_BUFFER,
						in_port=ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					sw_datapath.send_msg(out)
		elif arp_hdr.opcode == arp.ARP_REPLY:
			# it is a reply
			if arp_dst_ip in self.ip_to_datapath:
				datapath = self.ip_to_datapath[arp_dst_ip]

				actions = [parser.OFPActionOutput(in_port)]
				ARP_Reply = packet.Packet()
	
				# reply
				ARP_Reply.add_protocol(ethernet.ethernet(
					ethertype=0x0806,
					dst=eth_dst,
					src=eth_src))
				ARP_Reply.add_protocol(arp.arp(
					opcode=arp.ARP_REPLY,
					src_mac=eth_src,
					src_ip=arp_src_ip,
					dst_mac=eth_dst,
					dst_ip=arp_dst_ip))
	
				ARP_Reply.serialize()
				# send back
				out = parser.OFPPacketOut(
					datapath=datapath,
					buffer_id=ofproto.OFP_NO_BUFFER,
					in_port=ofproto.OFPP_CONTROLLER,
					actions=actions, data=ARP_Reply.data)
				datapath.send_msg(out)
				return True
		return False

	def ipv4_routing(self,msg,src,dst,datapath,dpid,ofproto,parser,in_port):
		if dst in self.net:
			print "%s -> %s" % (src,dst)
			print "nodes:"
			print self.net.nodes
			print "edges:"
			print self.net.edges
			try:
				path=nx.shortest_path(self.net,src,dst)
				# install the path
				next_index=path.index(dpid)+1
				current_dpid=dpid
				current_dp=datapath
				path_len=len(path)
				while next_index < path_len:
					if current_dp is None:
						continue
	
					next_dpid=path[next_index]
					out_port=self.net[current_dpid][next_dpid]['port']
					self.add_flow(
						datapath=current_dp,
						dst=dst,
						out_port=out_port
					)
	
					next_index += 1
					current_dpid=next_dpid
					if current_dpid in self.dpid_to_datapath:
						current_dp=self.dpid_to_datapath[current_dpid]
					else:
						current_dp=None
			except nx.NetworkXNoPath:
				print "No path"
				return
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
		# return the packet
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
			actions=actions)
		datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchEnter)
	def switch_enter(self, ev):
		datapath = ev.switch.dp
		dpid = datapath.id
		if dpid not in self.dpid_to_datapath:
			self.dpid_to_datapath[dpid] = datapath
		self.net.add_node(dpid)
	
	@set_ev_cls(event.EventSwitchLeave)
	def switch_leave(self,ev):
		datapath = ev.switch.dp
		dpid = datapath.id
		if dpid in self.dpid_to_datapath:
			del self.dpid_to_datapath[dpid]
		self.net.remove_node (dpid)

	@set_ev_cls(event.EventLinkAdd)
	def link_add(self,ev):
		src_port_no = ev.link.src.port_no
		src_dpid = ev.link.src.dpid
		dst_dpid = ev.link.dst.dpid
		self.net.add_edge(src_dpid,dst_dpid,port=src_port_no)