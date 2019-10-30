# Basic Threat Hunting Techniques: #

1. Identify communication channels
1. Establish a baseline
1. Analyze the protocol
1. Scrutinize the reputation of the destination
1. Determine disposition


## Score Rubrik (0 - 100) More than 100 points possible. ##
* Persistent Communications: (~ 60)
* Protocol: (~ 20)
* Reputation: (~ 10)
* Unique Subdomains: (~ 10)
* Unique User Agent: (~ 5)
* Large Byte Sizes: (~ 5)
* Denied / Malicous Inbound Connections: (~ 5)

## Persistent Communications ##
* Check Connection Duration (4+ hours is typically worth investigating)
* Check Amount of Times The Connection Was Destroyed and Then Recreated
* Check For Beacons
	* Check consistent times averaged over an hour
	* Check consistent sizes averaged over an hour


## Protocol ##
* Does the port match the protocol?
	* I.e DNS over tcp
* Does the common port match the service?
	* I.e SSH over 443

## Reputation ##
* What do VirusTotal, Talos, IPVoid, URLVoid, etc. say?

## Unique Subdomains ##
* How many unique subdomains are there to a single domain?
	* I.e foo.bar.com, biz.bar.com, baz.bar.com

## Unique User-Agents ##
* How many unique User-Agent strings are leaving your environment?
	* This will be more effective in a standarized environment.

## Large Byte Sizes ##
* How big is the ingress/egress traffic?

## Greynoise Hunting Techniques ##

* Download the malicious data from the past 24 hours
	* Compare against data set

* Download the benign data from the past 24 hours
	* Use as pool to compare incoming alerts.

* Perform hunting technique against data set to get a list of suspicious IP addresses
	* Perform API request to get disposition of IP


## Resources ##
1. https://www.youtube.com/watch?v=_h4cmNydZXg