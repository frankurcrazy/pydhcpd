#!/usr/bin/env python

import dhcp_packet
import socket
import random
import time
import Queue
import select

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind( ("", 68) )
sock.settimeout(5)

mac = "".join(random.choice("abcdef0123456789") for _ in xrange(0,12))
dest = ("<broadcast>", 67)
bufsize = 8192

while True:
	xid = random.randrange(2**32)
	t1 = 0

	# send dhcp_discover
	print "sending dhcp discover"
	dhcp_discover = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPDISCOVER,mac=mac,xid=xid,broadcast=True)
	print dhcp_discover
	sock.sendto(dhcp_discover.to_raw(),dest)

	# receive dhcp offer
	try:
		response = sock.recv(bufsize)
	except socket.timeout:
		print "timeout"
		continue

	response = dhcp_packet.from_raw_message(response)
	print response

	if response.xid == xid and response.message_type == dhcp_packet.DHCPOFFER:
		print "received correspondent dhcp offer"
		print response

		offer_ip = response.yiaddr
		server_identifier = [ value for (code, value) in response.options if code == dhcp_packet.__OPTION_SERVER_IDENTIFIER__ ]
		server_identifier = server_identifier[0] if server_identifier else None
		lease_time = [ value for (code, value) in response.options if code == dhcp_packet.__OPTION_LEASE_TIME__ ]
		t1_time = [ value for (code, value) in response.options if code == dhcp_packet.__OPTION_RENEW_TIME__ ]

		t1 = t1_time[0] if t1_time else lease_time[0]/2 if lease_time else 0

	# send dhcp request
	print "sending dhcp request"
	options = [
		(dhcp_packet.__OPTION_SERVER_IDENTIFIER__, server_identifier),
		(dhcp_packet.__OPTION_REQUESTED_ADDRESS__, offer_ip)
	]

	dhcp_request = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPREQUEST, mac=mac, xid=xid, broadcast=True, options=options)
	print dhcp_request
	sock.sendto(dhcp_request.to_raw(),dest)

	# recv dhcp ack
	try:
		response = sock.recv(bufsize)
	except socket.timeout:
		print "timeout"
		continue
	response = dhcp_packet.from_raw_message(response)

	if response.xid == xid and response.message_type == dhcp_packet.DHCPACK:
		print response
	
	while True:
		if t1 ==0: continue
		# send renew
		time.sleep(t1)

		print "lease time/2 or t1 reached, send renew (%(timestamp)s)" % { 'timestamp': time.ctime()}
		dhcp_request = dhcp_packet.dhcp_packet(message_type=dhcp_packet.DHCPREQUEST, mac=mac, xid=xid, broadcast=True, options=options)
		print dhcp_request
		sock.sendto(dhcp_request.to_raw(),dest)

		# recv ack
		try:
			response = sock.recv(bufsize)
		except socket.timeout:
			print "timeout"
			continue
		response = dhcp_packet.from_raw_message(response)
		if response.xid == xid and response.message_type == dhcp_packet.DHCPACK:
			print response


