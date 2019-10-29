# NAME - FirewallLog.py
# SYNOPSIS
## 
# DESCRIPTION
## 
# INPUT:
## an dict pertinent details
###	src String (Source IP)
### dst String (Destination IP)
### sport int (Source Port)
### dport int (Destination Port)
### protocol String (Protocol[tcp,udp,icmp])
### bytes_transferred int (Bytes transferred in the connection)
### time String (Time the log occured)
### log_type String (Log Type[flows, ip_flow_end, urls])
### action String ([allow, deny])
# OUTPUT:
## None
# AUTHOR: ncoats@guardsight.com
#
# (c) 2019 GuardSight, Inc.
#
# Import relevent libraries

import json, re, ipaddress

from datetime import datetime

class FirewallLog:

	ALLOWED_PORTS = [80, 443, 53]

	ALLOWED_EGRESS_PORTS = [80, 443, 53]

	ALLOWED_INGRESS_PORTS = [80, 443]

	MAX_SIZE_THRESHOLD = 100000

	PORT_PROTOCOL = {
		80 : "tcp",
		22 : "tcp",
		443 : "tcp",
		53 : "udp"
	}

	# Bytes Transferred
	bytes_transferred = 0

	# Source IP
	src = ""

	# Destination IP
	dst = ""

	# Protocol
	protocol = ""

	# Timestamp
	time = ""

	# I.e deny, allow
	action = ""

	# I.e flow, url
	log_type = ""

	# Source port
	sport = ""

	# Destination port
	dport = ""

	is_egress = True

	def __init__(self, data_set):
		self.src = data_set["src"]
		self.dst = data_set["dst"]
		self.sport = int(data_set["sport"])
		self.dport = int(data_set["dport"])
		self.protocol = data_set["protocol"].lower()
		self.bytes_transferred = int(data_set["bytes_transferred"])
		self.time = data_set["time"]
		self.log_type = data_set["log_type"].lower()
		self.action = data_set["action"].lower()

		if ipaddress.ip_address(self.src).is_private:
			self.is_egress = True
		else:
			self.is_egress = False


	def hasAnomly(self):
		if self.wasDenied() or self.hasPortAnomoly() or self.hasPortProtocolAnomoly() or self.hasByteAnomoly() or self.hasEgressAnomoly()or self.hasIngressAnomoly():
			return True
		return False


	def wasDenied(self):
		if self.action == "deny":
			return True
		return False

	def hasPortAnomoly(self):
		if self.is_egress and self.dport in self.ALLOWED_PORTS:
			return True

		if self.is_egress == False and self.sport in self.ALLOWED_PORTS:
			return True

		return False


	def hasPortProtocolAnomoly(self):
		try:
			if self.PORT_PROTOCOL[self.sport] != self.protocol:
				return True
		except:
			pass
		try:
			if self.PORT_PROTOCOL[self.dport] != self.protocol:
				return True
		except:
			pass

		return False

	def hasByteAnomoly(self):
		if self.bytes_transferred >= self.MAX_SIZE_THRESHOLD:
			return True
		return False

	def hasIngressAnomoly(self):
		if not self.is_egress and self.dport not in self.ALLOWED_INGRESS_PORTS:
			return True
		return False

	def hasEgressAnomoly(self):
		if self.is_egress and self.dport not in self.ALLOWED_EGRESS_PORTS:
			return True
		return False

