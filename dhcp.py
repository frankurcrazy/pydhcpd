#!/usr/bin/env python
#-*- coding:utf-8 -*-

import struct 
import socket
import random
import string 
import collections 

class dhcp_packet(object):
	# dhcp message type (option 53)
	DHCPDISCOVER = 1 
	DHCPOFFER = 2
	DHCPREQUEST = 3 
	DHCPDECLINE = 4
	DHCPACK = 5 
	DHCPNACK = 6
	DHCPRELEASE = 7
	DHCPINFORM = 8
	OPTION_END = "\xff"

	SUPPORTED_OPTION_CODE = [0, 1, 3, 6, 12, 53, 54, 58, 59, 255]

	DHCP_HEADER_FORMAT = "!4B1I2H4I16s64s128s"
	DHCP_HEADER_LENGTH = struct.calcsize(DHCP_HEADER_FORMAT)

	def __init__(self, xid=0, unicast=False, chaddr="helloworld"):
		# Generate random xid if xid not provided
		if xid == 0:
			self.xid = random.randrange(1, 2**32);

		# use unicast or broadcast?
		self.flags = 0 if unicast else 1<<15

		# mac address of the client interface
		self.chaddr = chaddr

	def __dhcp_packet__(self, packet_field):
		magic_cookie = "\x63\x82\x53\x63"
		options = packet_field['options'] + self.OPTION_END

		"""
		Op: 1 byte (1-request, 2-reply)
		Hw: 1 byte (1)
		Hardware Access Length: 1 byte (6)
		hops: 1 byte (0)
		
		xid(4): random number
		sec(2)
		flags(2) unicast or broadcast
		"""

		return struct.pack(self.DHCP_HEADER_FORMAT, 
				packet_field['op'],
				packet_field['htype'],
				packet_field['hlen'], 
				packet_field['hops'], 
				self.xid, 
				packet_field['secs'], 
				packet_field['flags'], 
				packet_field['ciaddr'],
				packet_field['yiaddr'],
				packet_field['siaddr'],
				packet_field['giaddr'],
				self.chaddr if not 'chaddr' in packet_field else packet_field['chaddr'],
				"" if not 'sname' in packet_field else packet_field['sname'],
				"" if not 'file' in packet_field else packet_field['file']) +magic_cookie+options
	
	def parseDHCPPacket(self, dhcp_message):
		if dhcp_message=="": return
		DHCPPacket = collections.namedtuple("DHCPPacket", 
			['op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags', 'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'chaddr', 'sname', 'file', 'options'])  

		options = []
		dhcp_header = struct.unpack(self.DHCP_HEADER_FORMAT, dhcp_message[:self.DHCP_HEADER_LENGTH])
		
		
		# Bypass Magic Cookie
		if dhcp_message[self.DHCP_HEADER_LENGTH:self.DHCP_HEADER_LENGTH+4] == "\x63\x82\x53\x63":
			options_raw = dhcp_message[self.DHCP_HEADER_LENGTH+4:]
		else:
			options_raw = dhcp_message[self.DHCP_HEADER_LENGTH:]

		cur_pos = 0 # option parsing cusor, constantly pointing to next option code
		while True:
			op_code = ord(options_raw[cur_pos])
			value = options_raw[cur_pos+2:cur_pos+2+ord(options_raw[cur_pos+1])]
			if op_code == 0: # option pad
				cur_pos += 1
			elif op_code == 255:
				break;
			elif op_code in [53]: # message type
				options[:-1] = [ (op_code, ord(value)) ]
			elif op_code in [51, 58, 59]: # lease/renew/rebind time
				options[:-1] = [ (op_code, struct.unpack("!I", value)[0]) ]
			elif op_code in [1, 3, 28, 54]: # subnet mask/router ip/broadcast address/server identifier
				options[:-1] = [ (op_code, socket.inet_ntoa(value)) ]
			else:
				options[:-1] = [(op_code, options_raw[cur_pos+2:cur_pos+2+ord(options_raw[cur_pos+1])])]

			# goto next option
			cur_pos += ord(options_raw[cur_pos+1]) + 2
			if cur_pos >= len(options_raw)-1: break

		return DHCPPacket(
					op=dhcp_header[0],
					htype=dhcp_header[1],
					hlen=dhcp_header[2],
					hops=dhcp_header[3],
					xid=dhcp_header[4],
					secs=dhcp_header[5],
					flags=dhcp_header[6],
					ciaddr=socket.inet_ntoa(struct.pack("!I",dhcp_header[7])),
					yiaddr=socket.inet_ntoa(struct.pack("!I",dhcp_header[8])),
					siaddr=socket.inet_ntoa(struct.pack("!I",dhcp_header[9])),
					giaddr=socket.inet_ntoa(struct.pack("!I",dhcp_header[10])),
					chaddr=dhcp_header[11],
					sname=dhcp_header[12],
					file=dhcp_header[13],
					options=options
				)

	def request(self, ciaddr=None, options=""):
		packet_field = {
			'op': 1,
			'htype': 1,
			'hlen': 6,
			'hops': 0,
			'secs':0,
			'flags': self.flags,
			'ciaddr': 0 if not ciaddr else ciaddr,
			'yiaddr': 0,
			'siaddr': 0,
			'giaddr': 0,
			'options': struct.pack("!B B B", 53, 1, self.DHCPREQUEST)+options
		}
		packet = self.__dhcp_packet__(packet_field)
		return packet

	def release(self):
		pass;

	def decline(self):
		pass;

	def discover(self,options=""):
		packet_field = {
			'op': 1,
			'htype': 1,
			'hlen': 6,
			'hops': 0,
			'secs':0,
			'flags': self.flags,
			'ciaddr': 0,
			'yiaddr': 0,
			'siaddr': 0,
			'giaddr': 0,
			'options': struct.pack("!B B B", 53, 1, self.DHCPDISCOVER)+options
		}
		packet = self.__dhcp_packet__(packet_field)
		return packet

	def offer(self):
		pass;

if __name__ == "__main__":
	# Generate new socket and enable broadcast and address reuse
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1);
	sock.bind(("0.0.0.0", 68))

	packet = dhcp_packet(unicast=False, chaddr=''.join(random.choice(string.ascii_letters) for _ in xrange(0,6)))
	print "Sending DHCPDISCOVER..."
	packet = dhcp_packet(unicast=False, chaddr=''.join(random.choice(string.ascii_letters) for _ in xrange(0,6)))
	discover_packet = packet.discover()
	sock.sendto(discover_packet, ("255.255.255.255", 67))

	m,s = sock.recvfrom(8192)
	print "Receive packet from %s:%d..." % s
	packet_format = "!4B1I2H4I16s64s128s"
	resp = struct.unpack(packet_format, m[:236])
	print packet.parseDHCPPacket(m)


	print "Send request packet..."
	request_packet = packet.request(ciaddr=resp[8])
	sock.sendto(request_packet, ("255.255.255.255", 67))
	m,s = sock.recvfrom(8192)
	print "Receive packet from %s:%d..." % s
	packet_format = "!4B1I2H4I16s64s128s"
	resp = struct.unpack(packet_format, m[:236])
	print packet.parseDHCPPacket(m)
	

