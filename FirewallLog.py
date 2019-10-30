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

	# User agent
	user_agent = ""

	is_egress = True

	def __init__(self, data_set):
		self.src = data_set["src"]
		self.dst = data_set["dst"]
		self.sport = int(data_set["sport"])
		self.dport = int(data_set["dport"])
		self.protocol = data_set["protocol"].lower()
		self.bytes_transferred = int(data_set["bytes_transferred"])

		if "user_agent" in data_set:
			self.user_agent = data_set["user_agent"]
		
		self.time = data_set["time"]
		self.log_type = data_set["log_type"].lower()
		self.action = data_set["action"].lower()

		if ipaddress.ip_address(self.src).is_private:
			self.is_egress = True
		else:
			self.is_egress = False

	# Input: None
	# Return: float
	def getRiskScore(self):
		risk_score = 0.0

		# Denied / Inbound: 5 Points
		if self.wasDenied() or self.hasIngressAnomoly():
			risk_score += 5.0

		# Large Byte Size: 5 Points
		if self.hasByteAnomoly():
			risk_score += 5.0

		# Protocol: (10 Points * 2) = 20 Points
		if self.hasPortProtocolAnomoly():
			risk_score += 10.0

		if self.hasEgressAnomoly():
			risk_score += 10.0

		return risk_score

	# Input: None
	# Return: Boolean
	def wasDenied(self):
		if self.action == "deny":
			return True
		return False

	# Input: None
	# Return: Boolean
	# def hasPortAnomoly(self):
	# 	if self.is_egress and self.dport not in self.ALLOWED_EGRESS_PORTS:
	# 		return True

	# 	if not self.is_egress and self.dport not in self.ALLOWED_INGRESS_PORTS:
	# 		return True

	# 	return False

	# Input: None
	# Return: Boolean
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

	# Input: None
	# Return: Boolean
	def hasByteAnomoly(self):
		if self.bytes_transferred >= self.MAX_SIZE_THRESHOLD:
			return True
		return False

	# Input: None
	# Return: Boolean
	def hasIngressAnomoly(self):
		if not self.is_egress and self.dport not in self.ALLOWED_INGRESS_PORTS:
			return True
		return False

	# Input: None
	# Return: Boolean
	def hasEgressAnomoly(self):
		if self.is_egress and self.dport not in self.ALLOWED_EGRESS_PORTS:
			return True
		return False

