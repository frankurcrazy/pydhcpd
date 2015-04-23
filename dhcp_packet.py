#!/usr/bin/env python
#-*- coding:utf-8 -*-

import struct 
import socket
import random
import string 
import collections 
import re

################################################
#
#	Constants
#
################################################

# op 
REQUEST = 1
REPLY = 2

# htype
ETHERNET = 1

# hlen

# hops

# magic cooke
MAGIC_COOKIE = "\x63\x82\x53\x63"

# options ( currently/willbe supported )
__OPTION_PADDING__= 0
__OPTION_NETMASK__ = 1
__OPTION_ROUTERS__ = 3 
__OPTION_DNS_SERVERS__ = 6
__OPTION_HOSTNAME__ = 12
__OPTION_BROADCAST_ADDRESS__ = 28
__OPTION_NTP_SERVERS__ = 42 
__OPTION_REQUESTED_ADDRESS__ = 50
__OPTION_LEASE_TIME__ = 51
__OPTION_MESSAGE_TYPE__ = 53
__OPTION_SERVER_IDENTIFIER__ = 54
__OPTION_RENEW_TIME__ = 58
__OPTION_REBIND_TIME__ = 59
__OPTION_RELAY_AGENT__ = 82
__OPTION_END__ = 255

# Option 53: Message Type
DHCPDISCOVER = 1 
DHCPOFFER = 2
DHCPREQUEST = 3 
DHCPDECLINE = 4
DHCPACK = 5 
DHCPNACK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

MESSAGE_TYPE = (
	"",
	"DHCPDISCOVER",
	"DHCPOFFER",
	"DHCPREQUEST",
	"DHCPDECLINE",
	"DHCPACK",
	"DHCPNACK",
	"DHCPRELEASE",
	"DHCPINFORM"
)

# Misc
__SUPPORTED_OPTION_CODE__ = [0, 1, 3, 6, 12, 53, 54, 58, 59, 255]
__DHCP_HEADER_FORMAT__ = "!4B1I2H4s4s4s4s16s64s128s"
DHCP_HEADER_LENGTH = struct.calcsize(__DHCP_HEADER_FORMAT__)

__dhcp_struct__ = struct.Struct(__DHCP_HEADER_FORMAT__)

###############################################
#
#	Functions
#
###############################################

"""
	parse raw message and return a dhcp_packet object
"""
def from_raw_message(raw_message):
	message_type = 0
	options_raw = ''
	if len(raw_message) < DHCP_HEADER_LENGTH: return None
	dhcp_header = __dhcp_struct__.unpack(raw_message[:DHCP_HEADER_LENGTH])

	# Bypass Magic Cookie
	if raw_message[DHCP_HEADER_LENGTH:DHCP_HEADER_LENGTH+4] == MAGIC_COOKIE:
		options_raw = raw_message[DHCP_HEADER_LENGTH+4:]
	else:
		options_raw = raw_message[DHCP_HEADER_LENGTH:]

	# parse raw options
	options = _parse_raw_options(options_raw)

	for option in options:
		if option[0]==__OPTION_MESSAGE_TYPE__:
			break
	if not option: raise Exception("No Message Type Specified in Packet")
	else: message_type = option[1]

	return dhcp_packet(message_type=message_type, htype=dhcp_header[1],
					hlen=dhcp_header[2], hops=dhcp_header[3],
					xid=dhcp_header[4], secs=dhcp_header[5], broadcast=True if dhcp_header[6]==1<<15 else False,
					ciaddr=socket.inet_ntoa(dhcp_header[7]),
					yiaddr=socket.inet_ntoa(dhcp_header[8]),
					siaddr=socket.inet_ntoa(dhcp_header[9]),
					giaddr=socket.inet_ntoa(dhcp_header[10]),
					mac=dhcp_header[11][0:6].encode('hex'), sname=dhcp_header[12], file=dhcp_header[13], options=options)
	
"""
	parse option list into raw packet
"""
def _parse_options(options):
	packet = ''
	for option in options:
		code, value = option

		# with single byte value
		if code in [__OPTION_MESSAGE_TYPE__]:
			packet += (struct.pack("!3B", code ,1,value))
			continue

		# with single ip address as value
		if code in [__OPTION_NETMASK__, __OPTION_BROADCAST_ADDRESS__, __OPTION_SERVER_IDENTIFIER__,__OPTION_REQUESTED_ADDRESS__]:
			packet += (struct.pack("!2B", code, 4)+socket.inet_aton(value))
			continue
			
		# with multiple ip address as value
		if code in [__OPTION_ROUTERS__, __OPTION_NTP_SERVERS__, __OPTION_DNS_SERVERS__]:
			if len(value) == 0: continue # continue if no ip specified
			packet += (struct.pack("!2B", code, 4*len(value)))
			for address in value:
				packet += socket.inet_aton(address)
			continue

		# time relevent
		if code in [__OPTION_LEASE_TIME__, __OPTION_RENEW_TIME__, __OPTION_REBIND_TIME__]:
			packet += struct.pack("!2BI", code, 4, value)
			continue

		# other options, for now just concat them to the packet
		# developer should take care of the null character in the end
		packet += (struct.pack("!2B", code, len(value))+value)

	return packet
	
"""
	parse options part from raw packet into option list
"""
def _parse_raw_options(raw_options):
	options = []
	cur_pos = 0
	while True:
		code = ord(raw_options[cur_pos])
		length = ord(raw_options[cur_pos+1])
		value = raw_options[cur_pos+2:cur_pos+length+2]

		if code == 0:
			cur_pos += 1
			continue

		elif code == 255:
			break

		# with single byte value
		elif code in [__OPTION_MESSAGE_TYPE__]:
			option = (code, ord(value))

		# with single ip address as value
		elif code in [__OPTION_NETMASK__, __OPTION_BROADCAST_ADDRESS__, __OPTION_SERVER_IDENTIFIER__,__OPTION_REQUESTED_ADDRESS__]:
			option = (code, socket.inet_ntoa(value))
			
		# with multiple ip address as value
		elif code in [__OPTION_ROUTERS__, __OPTION_NTP_SERVERS__, __OPTION_DNS_SERVERS__]:
			iplist = []
			for off in xrange(0, length/4):
				iplist +=  [socket.inet_ntoa(value[off*4:off*4+4])]
			option = (code, iplist)

		# time relevent
		elif code in [__OPTION_LEASE_TIME__, __OPTION_RENEW_TIME__, __OPTION_REBIND_TIME__]:
			option = (code, struct.unpack("!I", value)[0])

		else:
			option = (code, value)

		options += [option]
		cur_pos += length + 2
		if cur_pos >= len(raw_options) -1: break

	return options


###############################################
#
#	Classes
#
###############################################
class dhcp_packet(object):
	"""
		require: message_type, client_mac
	"""
	def __init__(self, message_type, mac, hlen=6, htype=1, hops=0, secs=0, xid=None, broadcast=True, 
				ciaddr=None, yiaddr=None, siaddr=None, giaddr=None, sname="", file="", options=[]):

		self.options = []
		if (message_type == DHCPDISCOVER):
			self.op = REQUEST
		elif (message_type == DHCPOFFER):
			self.op = REPLY
			# check server identifier option
		elif (message_type == DHCPREQUEST):
			self.op = REQUEST
		elif (message_type == DHCPDECLINE):
			self.op = REPLY
		elif (message_type == DHCPACK):
			self.op = REPLY
		elif (message_type == DHCPNACK):
			self.op = REPLY
		elif (message_type == DHCPRELEASE):
			self.op = REQUEST
		elif (message_type == DHCPINFORM):
			self.op = REQUEST
		else:
			# Unknown message type
			print message_type
			raise Exception("Unknown DHCP Message Type")

		# randomize xid if not given
		if not xid:
			self.xid = random.SystemRandom().randrange(2**32)
		else: self.xid = xid

		# add message type option into packet
		self.message_type = message_type
		opt = None
		for option in options:
			if option[0] == __OPTION_MESSAGE_TYPE__:
				opt = option
				break

		if not opt: # no message type found, create one
			self.options += [(__OPTION_MESSAGE_TYPE__, message_type)]
		elif opt[1] != message_type:
			raise Exception("Duplicate message type")

		# setting dhcp header
		self.hlen = hlen
		self.htype = htype
		self.hops = hops
		self.secs = secs
		self.flags = 1 << 15 if broadcast else 0
		self.sname = sname
		self.file = file

		# translate dotted-notation into native int
		self.ciaddr = "0.0.0.0" if not ciaddr else ciaddr
		self.yiaddr = "0.0.0.0" if not yiaddr else yiaddr
		self.siaddr = "0.0.0.0" if not siaddr else siaddr
		self.giaddr = "0.0.0.0" if not giaddr else giaddr

		# translate mac address into hex digit
		mac = mac.replace(":", "").replace(".","").decode('hex')
		if len(mac) != 6: raise Exception("MAC Format Error")
		self.chaddr = mac

		# add options into option list
		self.options += options

	def __str__(self):
		rep = ("Message type: %(mtype)d (%(typename)s)\n"+
		"[op: %(op)d,  htype: %(htype)d, hlen: %(hlen)d, hops: %(hops)d]\n"
		"[xid: %(xid)d]\n"+
		"[secs: %(secs)d, flags: %(flags)d]\n"+
		"[ciaddr: %(ciaddr)s, yiaddr:  %(yiaddr)s, siaddr: %(siaddr)s, giaddr: %(giaddr)s]\n"+
		"[chaddr: %(chaddr)s]\n"+
		"[sname: \"%(sname)s\"]\n"+
		"[file: \"%(file)s\"]\n"
		) % {
			'mtype': self.message_type,
			'typename': MESSAGE_TYPE[self.message_type],
			'op': self.op,
			'secs': self.secs,
			'flags': self.flags,
			'htype': self.htype,
			'hlen': self.hlen,
			'hops': self.hops,
			'xid': self.xid,
			'ciaddr': self.ciaddr,
			'yiaddr': self.yiaddr,
			'siaddr': self.siaddr,
			'giaddr': self.giaddr,
			'chaddr': repr(self.chaddr),
			'sname': self.sname,
			'file': self.file
			}

		for op in self.options:
			rep += "[options: %s]\n"%(repr(op))

		return rep

	def to_raw(self):
		packet =  __dhcp_struct__.pack(
				self.op, self.htype, self.hlen, self.hops,
				self.xid,
				self.secs, self.flags,
				socket.inet_aton(self.ciaddr),
				socket.inet_aton(self.yiaddr), 
				socket.inet_aton(self.siaddr), 
				socket.inet_aton(self.giaddr),
				self.chaddr,
				self.sname,
				self.file
				)

		packet += MAGIC_COOKIE
		packet += _parse_options(self.options)
		packet += chr(__OPTION_END__)
		return packet

	def __repr__(self):
		return repr(self.to_raw())	

	def mac_str(self):
		return ":".join( x.encode('hex') for x in self.chaddr )


class dhcp_client(object):
	pass

if __name__ == "__main__":
	# do nothing
	pass


