#!/usr/bin/env python
#-*- coding:utf-8 -*- 
import dhcp_packet
import socket
import struct
import select
import time
import Queue
import threading
import json

DEFAULT_LEASE_TIME=10
BUFSIZE = 65535

IP_POOL = ['10.1.1.1', '10.1.1.2', '10.1.1.3', '10.1.1.4']
SERVER_IDENTIFIER = '10.1.1.250'
ROUTER = '10.1.1.250'
DOMAIN_NAME_SERVER = ['8.8.8.8','8.8.4.4']
NETMASK = '255.255.255.0'

def load_setting(config_path):
	config = json.load(open(config_path, "r"))
	return dhcp_server(config)

class dhcp_lease(object):
	def __init__(self,  chaddr, ip, lease_start=time.time(), lease_time=DEFAULT_LEASE_TIME, hostname=None):
		self.hostname = 'NULL' if not hostname else hostname
		self.lease_start = self.last_update = lease_start
		self.counter = 1
		self.chaddr = chaddr
		self.lease_time = lease_time
		self.ip = ip

	def __str__(self):
		return self.__repr__()

	def __repr__(self):
		now = time.time()
		return "(ip=%(ip)s, hostname=\"%(hostname)s\", mac=\"%(mac)s\" lease_time_left=%(time)f, renew_counter=%(renew)d)" % {
					'ip':self.ip, 'time': self.lease_time-(now-self.last_update), 'hostname':self.hostname,
					'renew': self.counter, 'mac': ":".join( x.encode('hex') for x in self.chaddr)
				}

	def is_expired(self):
		return True	if self.lease_time-(time.time()-self.last_update) <= 0 else False

	def renew(self, lease_time=DEFAULT_LEASE_TIME):
		self.last_update = time.time()
		self.lease_time = lease_time
		self.counter += 1

class dhcp_server(object):
	def __init__(self, conf=None):
		self.lease_pool = []
		self.sessions = []
		self.static = []
		self.sock = None
		self.ip_pool = []
		self.server_identifier = SERVER_IDENTIFIER

		if conf:
			for pool in conf['pools']:	
				start = struct.unpack("!I", socket.inet_aton(pool['start']))[0]
				end = struct.unpack("!I", socket.inet_aton(pool['end']))[0]
				for i in xrange(start, end+1):
					self.ip_pool += [socket.inet_ntoa(struct.pack("!I", i))]
			self.netmask = conf['netmask'] 
			self.dns = conf['dns']
			self.server_identifier = conf['server_identifier']
			self.default_lease_time = conf['default_lease_time']
			self.routers = conf['routers']

			for entry in conf['static']:
				self.static += [(entry['ip'], entry['mac'])]

	def start(self, port=67):
		print "DHCP Server started on port %d..." % port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	# enable address use
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # enable broadcast 
		self.sock.bind(("<broadcast>", port))
		self.sock.setblocking(False)

		# main loop
		while True:
			# receiving a dhcp message
			readready, writeready, exceptredy = select.select([self.sock], [], [])

			for sock in readready:
				message, address = sock.recvfrom(BUFSIZE)
				dp = dhcp_packet.from_raw_message(message)	
				if not dp: continue

				# find existing session
				self.remove_expired_lease()
				match = [x for x in self.sessions if x[0] == dp.xid]
				if not match:
					# if not existing session found, launch new session
					q = Queue.Queue()
					t = threading.Thread(target=self.session_handler, args=(q,))
					t.start()
					self.sessions += [(dp.xid, t, q)]
					q.put((dp, address))
				else:
					# put dhcp message to message_queue of existing session
					match[0][2].put((dp,address))

	def broadcast_message(self, dp):
		print "[xid=%(xid)d] Sending %(mtype)s to [%(mac)s]. (%(timestamp)s)" % {
			'xid': dp.xid, 'mtype': dhcp_packet.MESSAGE_TYPE[dp.message_type],
			'mac': ":".join( m.encode('hex') for m in dp.chaddr),
			'timestamp': time.ctime()
		}
		self.sock.sendto(dp.to_raw(), ("<broadcast>", 68))
	
	def session_handler(self, message_queue):
		xid = 0
		state = 1	# 2 if waiting for request
		while True:
			if not message_queue.empty():
				dp, addr = message_queue.get()
				print "[xid=%(xid)d] Receiving %(mtype)s from %(addr)s[%(mac)s]. (%(timestamp)s)" % {
					'xid': dp.xid, 'mtype': dhcp_packet.MESSAGE_TYPE[dp.message_type],
					'addr': repr(addr), 'mac': ":".join( m.encode('hex') for m in dp.chaddr),
					'timestamp': time.ctime()
				}
				xid = dp.xid
				# add identifier
				op = [(dhcp_packet.__OPTION_SERVER_IDENTIFIER__, self.server_identifier)]
				# add lease time option
				op += [(dhcp_packet.__OPTION_LEASE_TIME__, self.default_lease_time)]
				# add renew time
				op += [(dhcp_packet.__OPTION_RENEW_TIME__, self.default_lease_time/2),
						(dhcp_packet.__OPTION_REBIND_TIME__, self.default_lease_time/8)]
				# add router option
				op += [(dhcp_packet.__OPTION_ROUTERS__, self.routers)]
				# add netmask option
				op += [(dhcp_packet.__OPTION_NETMASK__, self.netmask)]
				# add dns option
				op += [(dhcp_packet.__OPTION_DNS_SERVERS__, self.dns)]

				# DHCPDISCOVER
				if dp.message_type == dhcp_packet.DHCPDISCOVER:
					# if no previos lease exist, else send offer according to lease
					# existed

					# new lease
					# find available list
					dhcp_offer = None
					match_leases = self.find_lease(ip=None, chaddr=dp.chaddr)
					if not match_leases:
						available_ip = self.available_ip()
						if len(available_ip) == 0: break
						dhcp_offer = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPOFFER, 
								mac=dp.mac_str(), xid=dp.xid, yiaddr=available_ip[0], options=op)
					else:
						dhcp_offer = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPOFFER, 
								mac=dp.mac_str(), xid=dp.xid, yiaddr=match_leases[0][1].ip, options=op)
					self.broadcast_message(dhcp_offer)
					state = 2 
					time.sleep(3)

				# DHCPREQUEST
				elif dp.message_type == dhcp_packet.DHCPREQUEST:
					available_ip = self.available_ip()
					requested_ip = [value for (code, value) in dp.options if code == dhcp_packet.__OPTION_REQUESTED_ADDRESS__]
					requested_ip = None if not requested_ip else requested_ip[0]

					server_identifier = [value for (code, value) in dp.options if code == dhcp_packet.__OPTION_SERVER_IDENTIFIER__]
					hostname = [value for (code, value) in dp.options if code == dhcp_packet.__OPTION_HOSTNAME__]

					# break if mismatch server identifier
					if not len(server_identifier) == 0 and not server_identifier[0] == self.server_identifier: break 

					# set hostname
					if hostname:
						hostname = hostname[0]


					# Search match leases
					match_leases = self.find_lease(ip=requested_ip, chaddr=dp.chaddr, strict=True)
					if match_leases:
						dhcp_ack = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPACK,
									mac=dp.mac_str(), xid=dp.xid, yiaddr=requested_ip, options=op)
						match_leases[0][1].renew(lease_time=self.default_lease_time) # renew lease
						print match_leases
						self.broadcast_message(dhcp_ack)
						break

					if requested_ip in available_ip:
						# lease valid
						dhcp_ack = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPACK,
									mac=dp.mac_str(), xid=dp.xid, yiaddr=requested_ip, options=op)
						self.broadcast_message(dhcp_ack)
						self.add_lease(ip=requested_ip, chaddr=dhcp_ack.chaddr, hostname=hostname)
						print "[IP Usage: %d/%d]" % (len(self.lease_pool), len(self.ip_pool))
						break

					else: # requested ip not available
						dhcp_nack = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPNACK,
									mac=dp.mac_str(), xid=dp.xid, options=op)
						self.broadcast_message(dhcp_nack)
						break

				elif dp.message_type == dhcp_packet.DHCPRELEASE:
					self.remove_lease(ip=dp.ciaddr, chaddr=dp.chaddr)
					break

				else: break
			elif state==2: break

		# delete session before exit
		matched_session_index = [i for i, (x, thread, queue) in enumerate(self.sessions) if x == xid][0]
		del self.sessions[matched_session_index]

	def find_lease(self,ip=None, chaddr=None, strict=False):
		if not ip and not chaddr:
			return None
		else:
			if strict:
				return [(i, lease) for i, lease in enumerate(self.lease_pool) if (lease.ip == ip and lease.chaddr == chaddr)]
			else:
				return [(i, lease) for i, lease in enumerate(self.lease_pool) if (lease.ip == ip or lease.chaddr == chaddr)]
		
	def add_lease(self, ip, chaddr, lease_time=DEFAULT_LEASE_TIME, hostname=None, lease_start=time.time()):
		self.lease_pool += [dhcp_lease(ip=ip, chaddr=chaddr, lease_start=time.time(), lease_time=lease_time, hostname=hostname)]
		print self.lease_pool

	def remove_lease(self, ip=None, chaddr=None):
		leases = self.find_lease(ip, chaddr)
		if not leases: return
		for i, lease in leases:
			del self.lease_pool[i]

	def remove_expired_lease(self):
		for lease in self.lease_pool:
			if lease.is_expired(): self.lease_pool.remove(lease)
		
					
	def renew_lease(self, ip, chaddr):
		leases = self.find_lease(ip=ip, chaddr=chaddr)
		if not leases: raise Exception("Lease not found")
		for i, lease in leases:
			lease.renew(self.default_lease_time)

	def available_ip(self):
		used_ip = [lease.ip for lease in self.lease_pool]
		return list(set(self.ip_pool).difference(set(used_ip)))

if __name__=="__main__":
	server = load_setting("config.json")
	server.start()
