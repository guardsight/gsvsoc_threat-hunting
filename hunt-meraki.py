#!/usr/bin/env python3
#
# NAME - hunt-meraki.py
# SYNOPSIS
## 
# DESCRIPTION
## 
# INPUT:
## stdin for meraki firewall logs
# OUTPUT:
## None
# AUTHOR: ncoats@guardsight.com
#
# (c) 2019 GuardSight, Inc.
#
# Import relevent libraries

import sys, re, time
from FirewallLog import FirewallLog

logs = []
suspicious_ips = []

for line in sys.stdin:

	# Simplistic to match src_ip, dst_ip, dport, sport
	result = re.findall('(([_a-z]{3,})=([^ ]*))', line)

	data_set = {}

	for full,index,val in result:
		data_set[index] = val

	# Get Time
	results = re.findall('(\d{8,}\.\d{8,})(.*)src=', line)
	# results = re.findall('\d{8,}\.\d{8,}', line)
	t,log_type = results[0]
	data_set["time"] = time.ctime(float(t))

	log_types = log_type.strip().split(" ")

	data_set["bytes_transferred"] = 0
	
	data_set["log_type"] = log_types[0]

	try:
		data_set["action"] = log_types[1]
	except:
		data_set["action"] = "allow"

	fl = FirewallLog(data_set)
	if fl.hasAnomly():
		logs.append(fl)


print(logs)
