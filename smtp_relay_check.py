#!/usr/bin/env python3

# Note: part of this code was (initially) taken from https://github.com/tango-j/SMTP-Open-Relay-Attack-Test-Tool/blob/master/OpenRelay.py, but it was highly modified 

''' SMTP Open Relay Check 

coded by d7x
https://d7x.promiselabs.net/

Usage: python smtp_relay_check.py <target> <port>

'''

import socket
import smtplib
from smtplib import *
import sys
from tld import get_tld, get_fld

## console colors
RED='\033[0;31m'
NC='\033[0m'

## function to send email
def sendEmail(IP, Port, rcpt_from, rcpt_to):
	print("Trying relay %s -> %s" %(rcpt_from, rcpt_to), end='' )

	s = socket.socket()
	s.connect((IP,int(Port)))
	socket.setdefaulttimeout(20)

	ans = s.recv(1024).decode()

	# connect to smtp
	smtpserver = smtplib.SMTP(IP,int(Port))

	do_cmd = smtpserver.docmd("Mail From: %s" %rcpt_from)
	cmd_r = str(do_cmd)
	if ("250" in cmd_r):
		do_cmd_to = smtpserver.docmd("RCPT TO: %s" %rcpt_to)
		cmd_rto = str(do_cmd_to)
		if ("250" in cmd_rto):    
			print("%s [+] The target seems to be vulenarble to Open relay attack %s" %(RED, NC) )

		else:
			print(" [-] N/A: %s " %cmd_rto)

	else:
		print(" # Err: %s" %cmd_r)

## main()
def main():
	# Emails 
	ext_email_dst = "<YOUR EMAIL>"
	ext_email_src = "john.doe@gmail.com"
	int_email_src = ["root"]
	int_email_dst = ["postmaster"]
	hosts = []

	# Test cases: (refer to https://www.blackhillsinfosec.com/how-to-test-for-open-mail-relays/)
	# - External Source Address, External Destination Address
	# - External Source Address, Internal Destination Address
	# - Internal Source Address, Internal Destination Address
	# - Internal Source Address, External Destination address
	
	IP = sys.argv[1]
	Port = sys.argv[2]

	# X = input("From: ")
	# Y = input("TO: ")

	# list of internal addresses
	# mails_ext = []
	mails_int = ["root", "postmaster"]

	s = socket.socket()
	s.connect((IP,int(Port)))
	socket.setdefaulttimeout(3)

	ans = s.recv(1024).decode()


	if ("220" in ans):
		#print(ans)
		host = ans.split()[1]
		print("Detected host [%s]" % host)
		hosts.append(host)

		# get TLD
		try:
			host_tld = get_fld(host, fix_protocol=True)
			hosts.append(host_tld)
		except:
			pass

		print("\n[+]Port" + " " + str(Port) + " " + "open on the target system\n")

		# connect to smtp
		smtpserver = smtplib.SMTP(IP,int(Port))

		# say helo
		print("Saying helo default...")
		host_helo = ""
		docmd_helo = smtpserver.docmd("helo default")
		buf = str(docmd_helo)
		host_helo = (buf.split(' ')[1].replace("b'",""))
		print("Helo host %s" % host_helo)
		hosts.append(host_helo)

		# get TLD
		try:
			host_tld = get_fld(host_helo, fix_protocol=True)
			hosts.append(host_tld)
		except: 
			pass

		# convert to set to get unique values
		hosts = set(hosts)
		# print(hosts)

		# Ext src -> ext dst
		sendEmail(IP, Port, ext_email_src, ext_email_dst)

		# Ext src -> int dst; Int src -> Int dst; Int src -> ext dst 
		for h in hosts:
			rcpt = mails_int[0] + '@' + h
			int_email_f = int_email_src[0] + '@' + h
			int_email_t = int_email_dst[0] + '@' + h
			sendEmail(IP, Port, ext_email_src, rcpt) # Ext src -> int dst
			sendEmail(IP, Port, int_email_f, int_email_t) # Int src -> int dst 
			sendEmail(IP, Port, int_email_f, ext_email_dst) # Int src -> ext dst 
			# debug print("%s " %h)
	    
	else:
		print("[-] Port is closed/Filtered")

if __name__ == "__main__":
    main()
