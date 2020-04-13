################
####   ASA  ####
################

[samplelog.cisco.asa]
sourcetype=cisco:asa
interval = 150
earliest = -60m
latest = now

##replace timestamp
token.0.token = ^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})
token.0.replacementType = timestamp
token.0.replacement = %b %d %H:%M:%S

##repalce user
token.1.token = (UUUUUUUU)
token.1.replacementType = file
token.1.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\userName.sample

##replace local address
token.2.token = \sladdr\s(XXX\.XXX\.XXX\.XXX)
token.2.replacementType = file
token.2.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replace foreign address
token.3.token = \sfaddr\s(XXX\.XXX\.XXX\.XXX)
token.3.replacementType = random
token.3.replacement = ipv4

##replace outside ips
token.4.token = (?:O|o)utside\S*(?::|/)(XXX\.XXX\.XXX\.XXX)
token.4.replacementType = random
token.4.replacement = ipv4

##replace inside ips
token.5.token = (?:I|i)nside\S*(?::|/)(XXX\.XXX\.XXX\.XXX)
token.5.replacementType = file
token.5.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replace username part of email
token.6.token = YYYYYYYYYY
token.6.replacementType = file
token.6.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\userName.sample

##replacing remaining ip
token.7.token = XXX\.XXX\.XXX\.XXX
token.7.replacementType = random
token.7.replacement = ipv4

##replacing Hostname
token.8.token = (HHHHHHHH)
token.8.replacementType = file
token.8.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\hostname.sample

##replacing ipv6
token.9.token = VVVVVVVVVV
token.9.replacementType = random
token.9.replacement = ipv6

##replacing internal IP
token.10.token = (##INTERNAL_IP##)
token.10.replacementType = file
token.10.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replacing IPv6
token.11.token = (##IP_V6##)
token.11.replacementType = random
token.11.replacement = ipv6

################
####  FWSM  ####
################

[samplelog.cisco.fwsm]
sourcetype=cisco:fwsm
interval = 150
earliest = -60m
latest = now

#replace timestamp 1
token.0.token = (\w{3}\s+\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})
token.0.replacementType = timestamp
token.0.replacement = %b %d %H:%M:%S

##replace timestamp 2
token.1.token = (\w{3}\s\d{1,2}\s\d{1,4}\s\d{1,2}:\d{1,2}:\d{1,2})
token.1.replacementType = timestamp
token.1.replacement = %b %d %Y %H:%M:%S

##replace user
token.2.token = (UUUUUUUU)
token.2.replacementType = file
token.2.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\userName.sample

##replace local address
token.3.token = \sladdr\s(XXX\.XXX\.XXX\.XXX)
token.3.replacementType = file
token.3.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replace foreign address
token.4.token = \sfaddr\s(XXX\.XXX\.XXX\.XXX)
token.4.replacementType = random
token.4.replacement = ipv4

##replace outside ips
token.5.token = (?:O|o)utside\S*(?::|/)(XXX\.XXX\.XXX\.XXX)
token.5.replacementType = random
token.5.replacement = ipv4

##replace inside ips
token.6.token = (?:I|i)nside\S*(?::|/)(XXX\.XXX\.XXX\.XXX)
token.6.replacementType = file
token.6.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replacing remaining ip
token.7.token = XXX\.XXX\.XXX\.XXX
token.7.replacementType = random
token.7.replacement = ipv4

##replacing Hostname
token.8.token = (HHHHHHHH)
token.8.replacementType = file
token.8.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\hostname.sample

################
####   PIX  ####
################

[samplelog.cisco.pix]
sourcetype=cisco:pix
interval = 150
earliest = -60m
latest = now

#replace timestamp 1
token.0.token = (\w{3}\s+\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})
token.0.replacementType = timestamp
token.0.replacement = %b %d %H:%M:%S

##replace user
token.1.token = (UUUUUUUU)
token.1.replacementType = file
token.1.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\userName.sample

##replace outside ips
token.2.token = outside\s?:\s?(?:Allocated ip = )?(XXX\.XXX\.XXX\.XXX)
token.2.replacementType = random
token.2.replacement = ipv4

##replace inside ips
token.3.token = inside\s?:\s?(?:.*\()?(XXX\.XXX\.XXX\.XXX)
token.3.replacementType = file
token.3.replacement = $SPLUNK_HOME\etc\apps\Splunk_TA_cisco-asa\samples\internal_ips.sample

##replacing remaining ip
token.4.token = XXX\.XXX\.XXX\.XXX
token.4.replacementType = random
token.4.replacement = ipv4
