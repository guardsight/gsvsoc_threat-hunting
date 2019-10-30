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

import sys, re, time, datetime
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
	if not results:
		continue

	t,log_type = results[0]
	data_set["time"] = datetime.datetime.strptime(time.ctime(float(t)), "%a %b %d %H:%M:%S %Y")

	log_types = log_type.strip().split(" ")

	data_set["bytes_transferred"] = 0
	
	data_set["log_type"] = log_types[0]

	try:
		data_set["action"] = log_types[1]
	except:
		data_set["action"] = "allow"

	fl = FirewallLog(data_set)


	# At this point we have only analyzed 40 of the total points available, so that is why 15 instead of 50
	# score = fl.getRiskScore()
	# if score >= 5:
	# 	logs.append(fl)
	logs.append(fl)

def checkIPForBeacon(times):
	times.sort()
	first = times[0]
	last = times[-1]
	diff = last - first
	
	point_value = 100 / len(times)

	probability = 0.0

	try:
		avg = len(times) / diff
		
		for i, t in enumerate(times[:-1]):
			if t !=  t[i+1] and (t + (t * .15)) >= t[i+1] :
				probability += point_value

		return probability > 50
	except:
		return False

	# for t in times:
	# 	print(t)

# Checking for Beacons
ip_sets = {}
for log in logs:
	key =  log.src + "-" + log.dst
	if key in ip_sets:
		ip_sets[key].append(log.time.timestamp() * 1000)
	else:
		ip_sets[key] = [log.time.timestamp() * 1000]

for k,times in ip_sets.items():
	if len(times) > 10:
		if checkIPForBeacon(times):
			suspicious_ips.append(k)

print(k)