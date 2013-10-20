#! /usr/bin/env python

# This script is designed to run in Python 2.4.3, meaning:
#   optparse instead of argparse
#   struct instead of bytes
#   d2b() instead of bin()
#   No ternary statement
#   Old string formatting

import optparse, random, struct, socket, sys


# Only used in a few places, made global instead of passing as arguments
debug = False
daemon = False
daemonSocket = None
returnAddr = None

# Constants
DNS_PORT = 53
MY_PORT = 7687
RECV_BUF = 1024
ROOT_E = '192.203.230.10'
# Map types to ints and ints to types
TYPE = { 'A': 1,
         'NS': 2,
         'CNAME': 5,
         'AAAA': 28 }
TYPE_NAMES = { 1: 'A',
               2: 'NS',
               5: 'CNAME',
               28: 'AAAA' }
# Map classes to ints and ints to classes
CLASS = { 'IN': 1 }
CLASS_NAMES = { 1: 'IN' }
# Map return codes to messages
RCODE = { 0: 'No errors',
          1: 'Format error - The name server was unable to interpret the query',
          2: 'Server failure - The name server was unable to process this query due to a problem with the name server',
          # Only meaningful for responses from authoritative name servers
          3: 'Name error - The domain name referenced in the query does not exist',
          4: 'Not Implemented - The name server does not support the requested kind of query',
          5: 'Refused - The name server refuses to perform the specified operation for policy reasons' }
# Indices in lists used to store results
# TODO: Use resource record objects
QNAME = 0
QTYPE = 1
QCLASS = 2
ANAME = 0
ATYPE = 1
ACLASS = 2
ATTL = 3
ADATA = 5


# Print the given question in a human-readable format
def printQuestion(question):
	print "\t" + question[QNAME], CLASS_NAMES[question[QCLASS]], TYPE_NAMES[question[QTYPE]]


# Print the given answer in a human-readable format
def printAnswer(answer):
	print "\t" + answer[ANAME], answer[ATTL], CLASS_NAMES[answer[ACLASS]],
	try:
		print TYPE_NAMES[answer[ATYPE]],
	except KeyError:
		# This is for types that aren't handled yet
		print "type", answer[ATYPE],
	if len(answer) == 6:
		print answer[ADATA]
	else:
		print


# Convert unsigned int n to binary string representation (big endian) and return it
# Optionally specify number of total bits, will be padded to the left with zeros
# Based on http://stackoverflow.com/a/1519418/1693087
def d2b(n, numBits = 0):
	bStr = ''
	if n < 0:
		raise ValueError, "must be a positive integer"
	if numBits and n > (2**numBits - 1):
		raise ValueError, "not enough bits to represent " + str(n)
	if n == 0:
		if numBits:
			return '0' * numBits
		else:
			return '0'
	while n > 0:
		bStr = str(n % 2) + bStr
		n = n >> 1

	return bStr.zfill(numBits)


# Parse label from byteString, then return both of them
# The original response is only used for parsing pointers
def parseLabel(byteString, origResponse = None):
	label = ''
	while True:
		# If the binary representation of first two bytes starts with '11', name points to a label
		checkPointer = d2b(struct.unpack("!H", byteString[:2])[0], 16)
		if checkPointer[:2] == '11':
			if not origResponse:
				raise ValueError, "must pass the original response to parseLabel"
			# Consume the two bytes and determine the offset of the name within the response
			byteString = byteString[2:]
			offset = int(checkPointer[2:], 2)
			# The question section has been consumed, so refer to the original response string
			plabel, _ = parseLabel(origResponse[offset:], origResponse)
			if len(label) > 0:
				label += '.' + plabel
			else:
				label += plabel
			# Pointers terminate labels, so break and return after parsing the value
			break
		# Otherwise, name is a label, read it normally
		else:
			# Length byte followed by that number of bytes
			qlen, byteString = struct.unpack("!B", byteString[:1])[0], byteString[1:]
			if qlen == 0:
				break
			if len(label) > 0:
				label += '.' + byteString[:qlen]
			else:
				label += byteString[:qlen]
			byteString = byteString[qlen:]

	return label, byteString


# Parse recordCount resource records from response and store them in outputList
# The original response is only here to be passed along to parseLabel()
def parseRRs(outputList, recordCount, response, origResponse):
	# Loop recordCount times
	# print "loop", recordCount, "times"
	for rec in range(recordCount):
		# print "----- RR", rec+1
		# [name, rtype, rclass, ttl, rdlen, rdata]
		outputList.append([])

		# Variable-length name
		name, response = parseLabel(response, origResponse)
		outputList[rec].append(name)
		# print "name", name

		# 16-bit type of the RDATA field
		rtype, response = struct.unpack("!H", response[:2])[0], response[2:]
		outputList[rec].append(rtype)
		# print "type", rtype

		# 16-bit class of the RDATA field
		rclass, response = struct.unpack("!H", response[:2])[0], response[2:]
		outputList[rec].append(rclass)
		# print "class", rclass

		# Unsigned 32-bit value specifying the TTL in seconds
		ttl, response = struct.unpack("!I", response[:4])[0], response[4:]
		outputList[rec].append(ttl)
		# print "ttl", ttl

		# Unsigned 16-bit value specifying the length of the RDATA field
		rdlen, response = struct.unpack("!H", response[:2])[0], response[2:]
		outputList[rec].append(rdlen)
		# print "len", rdlen

		# Variable-length data (depending on type of record)
		# A-type records return an IP address as a 32-bit unsigned value
		if rtype == TYPE['A']:
			try:
				ip = socket.inet_ntoa(response[:4])
				# print "ip", ip
				outputList[rec].append(ip)
			except socket.error:
				print "Error: Incorrect format for A-type RDATA"
				print outputList
				print repr(response)
				sys.exit(1)
		# NS and CNAME records return labels
		elif rtype == TYPE['NS'] or rtype == TYPE['CNAME']:
			# The modified response is ignored here
			name, _ = parseLabel(response, origResponse)
			# print "name", name
			outputList[rec].append(name)

		# Consume rdlen bytes of data
		response = response[rdlen:]

	return response


# Build the DNS datagram
def buildPacket(hostname, queryType):
	# Build the header
	header = ''

	# 16-bit value identifying the query (0 to 65535)
	identifier = random.randrange(65535)

	# The "!H" identifier indicates an unsigned short (2 bytes, 16 bits) formatted for network (big-endian)
	header += struct.pack("!H", identifier)

	# One bit specifying that this is a query (0)
	qr = '0'
	# Four-bit opcode specifying this is a standard query (0000)
	opcode = '0000'
	# One bit for responses that give an authoritative answer (doesn't apply here)
	aa = '0'
	# One bit indicating whether or not the message was truncated (it won't be)
	tc = '0'
	# One bit indicating if recursion is desired (no recursion desired)
	rd = '0'
	# One bit used in responses to indicate that recursion is available (doesn't apply here)
	ra = '0'
	# 3 bits reserved for future use, must be zero in all queries and responses
	z = '000'
	# 4-bit response code (doesn't matter here)
	rc = '0000'
	# Combine the flags
	header += struct.pack("!H", int(qr + opcode + aa + tc + rd + ra + z + rc, 2))

	# Unsigned 16-bit value specifying the number of questions (1)
	qdcount = 1
	header += struct.pack("!H", qdcount)

	# Unsigned 16-bit value specifying the number of answer records (doesn't apply here)
	ancount = 0
	header += struct.pack("!H", ancount)

	# Unsigned 16-bit value specifying the number of authority records (doesn't apply here)
	nscount = 0
	header += struct.pack("!H", nscount)

	# Unsigned 16-bit value specifying the number of additional records (doesn't apply here)
	arcount = 0
	header += struct.pack("!H", arcount)

	# Build the question segment
	questionSegment = ''

	# A sequence of labels, where each label consists of a length byte followed by that number of bytes
	for piece in hostname.split('.'):
		# IMPORTANT: Top two bits of the length in binary must be '00' to indicate a label
		# Therefore, no part of the domain name may exceed 63 bytes
		if len(piece) > 63:
			raise ValueError, "part of the domain name exceeds the maximum allowed length (63)"
		# First comes the length byte, "!B" identifier indicates network-formatted (big-endian) unsigned char (1 byte)
		questionSegment += struct.pack("!B", len(piece))
		# Then the bytes for the name
		for char in piece:
			questionSegment += struct.pack("!B", ord(char))
	# End of the hostname
	questionSegment += struct.pack("!B", 0)

	# Two-byte field specifying query type
	qtype = queryType
	questionSegment += struct.pack("!H", qtype)

	# Two-byte field specifying query class (IN = 1)
	qclass = CLASS['IN']
	questionSegment += struct.pack("!H", qclass)

	return header + questionSegment


# Send the given packet to the given nameserver and return the response
def sendPacket(nameserver, packet):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto(packet, (nameserver, DNS_PORT))
	data, addr = sock.recvfrom(RECV_BUF)
	return data


# Parse the given response and act accordingly
def parseResponse(response, hostname, nameserver):
	# Trim the response as it is parsed to make slicing nicer, but keep a copy of the original
	origResponse = response

	# Parse the header
	# Identifier
	identifier, response = struct.unpack("!H", response[:2])[0], response[2:]

	# Flags
	flags, response = struct.unpack("!H", response[:2])[0], response[2:]
	flags = d2b(flags, 16)
	qr, opcode, aa, tc, rd, ra, z, rc = flags[0], flags[1:5], flags[5], flags[6], flags[7], flags[8], flags[9:12], flags[12:]
	# Number of questions
	qdcount, response = struct.unpack("!H", response[:2])[0], response[2:]
	# Number of answers
	ancount, response = struct.unpack("!H", response[:2])[0], response[2:]
	# Number of authority records
	nscount, response = struct.unpack("!H", response[:2])[0], response[2:]
	# Number of additional records
	arcount, response = struct.unpack("!H", response[:2])[0], response[2:]

	# print "ID:", identifier
	# print "Return code:", int(rc, 2), "(" + RCODE[int(rc, 2)] + ")"
	# print "Truncated:", 
	# if int(tc):
	# 	print 'Yes'
	# else:
	# 	print 'No'
	# print "Answer RRs:", ancount
	# print "Authoritative:",
	# if int(aa):
	# 	print 'Yes'
	# else:
	# 	print 'No'
	# print "Authority RRs:", nscount
	# print "Additional RRs:", arcount

	# Parse the questions, same as when building the packet
	questions = []
	# Loop qdcount times
	for q in range(qdcount):
		# [name, qtype, qclass]
		questions.append([])

		# Name
		name, response = parseLabel(response)
		questions[q].append(name)

		# Type
		qtype, response = struct.unpack("!H", response[:2])[0], response[2:]
		questions[q].append(qtype)

		# Class
		qclass, response = struct.unpack("!H", response[:2])[0], response[2:]
		questions[q].append(qclass)
	
	if debug:
		print "Questions asked to " + nameserver + ":"
		for question in questions:
			printQuestion(question)

	# There normally won't be multiple questions, so this only inspects the first one
	# TODO: for eachQuestion in questions...
	qtype = questions[0][1]

	answers = []
	authorities = []
	additionals = []

	# print "Parse", ancount, "answers"
	response = parseRRs(answers, ancount, response, origResponse)
	# print "Parse", nscount, "authority RRs"
	response = parseRRs(authorities, nscount, response, origResponse)
	# print "Parse", arcount, "additional RRs"
	response = parseRRs(additionals, arcount, response, origResponse)

	if debug:
		if ancount:
			print "Answer RRs:"
			for answer in answers:
				printAnswer(answer)
		else:
			print "No answer RRs"

		if nscount:
			print "Authority RRs:"
			for auth in authorities:
				printAnswer(auth)
		else:
			print "No authority RRs"

		if arcount:
			print "Additional RRs:"
			for add in additionals:
				printAnswer(add)
		else:
			print "No additional RRs"

		print

	# For A-type requests, check for answers
	if qtype == TYPE['A']:
		# Display any answers that are present
		if ancount:
			# If running as a daemon, return the record
			if daemon:
				daemonSocket.sendto(origResponse, returnAddr)
			# Otherwise, print it like everything else
			else:
				if int(aa):
					print "Authoritative answer:"
				else:
					print "Non-authoritative answer:"
				for answer in answers:
					if answer[ATYPE] == TYPE['CNAME']:
						# If the only answer is a CNAME alias for another hostname, we need the A record for that alias
						# Untested, and there's a good chance this will mess up the output
						if ancount == 1:
							packet = buildPacket(answer[ADATA], TYPE['A'])
							response = sendPacket(nameserver, packet)
							parseResponse(response, answer[ADATA], nameserver)
							break
						# Otherwise, we'll just show the other answers
						else:
							continue
					print answer[ADATA]
		# Otherwise, determine who we should be asking 
		else:
			# If the server knows who to ask, assume the relevant NS records are included
			# Along with those NS records, assume the additional records include the IP address
			# Setting the type to NS ensures that the next if-block is entered
			if nscount:
				qtype = TYPE['NS']
			# Otherwise, we need to make an NS request to the root nameservers
			else:
				packet = buildPacket(hostname, TYPE['NS'])
				response = sendPacket(ROOT_E, packet)
				parseResponse(response, hostname, ROOT_E)

	# For NS-type requests, check the authority section
	# Assume that if a nameserver is known, so is its IP
	# Raise an exception if no NS records are returned
	if qtype == TYPE['NS']:
		if nscount:
			nsIP = ''
			# Loop over the NS records and find one with a corresponding A record
			for ns in authorities:
				for a in additionals:
					if a[ATYPE] == TYPE['A'] and a[ANAME] == ns[ADATA]:
						nsIP = a[ADATA]
						break
				if len(nsIP) > 0:
					break

			packet = buildPacket(hostname, TYPE['A'])
			response = sendPacket(nsIP, packet)
			parseResponse(response, hostname, nsIP)
		else:
			# We should never reach this point because the first query is an A request
			# If that query returns no answers, we query the root nameserver
			# All results after that should chain together correctly
			raise RuntimeError("NS request did not return any records")

	# TODO: Possibly refactor repeated building/sending/parsing into single block right here
	# TODO: If so, would need to halt execution after printing answers above


def main():
	# Globals only need to be declared if they're modified
	global debug
	global daemon
	global daemonSocket
	global returnAddr

	# Parse command-line arguments
	parser = optparse.OptionParser(description = 'Basic dig implementation using Python',
		usage = "usage: %prog hostname nameserver")
	parser.add_option("-d", action = "store_true", dest = "debug", default = False,
		help = "show debug output listing all answers")
	parser.add_option("-f", action = "store_true", dest = "daemon", default = False,
		help = "run as a daemon")

	(options, args) = parser.parse_args()

	# Check mode and number of arguments
	debug = options.debug
	daemon = options.daemon
	if (daemon and len(args) != 1) or (not daemon and len(args) != 2):
		parser.error("Wrong number of arguments")

	# Daemon mode is meant to run in the background and respond to requests passed to it
	if daemon:
		# The single command line arg is the nameserver to query
		nameserver = args[0]
		hostname = ''

		# Bind to MY_PORT and listen over UDP
		daemonSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		print "Port", MY_PORT, "selected"
		daemonSocket.bind(('', MY_PORT))

		while True:
			# returnAddr is the address to send back to
			data, returnAddr = daemonSocket.recvfrom(RECV_BUF)
			# Assume we've been sent a DNS packet, pass it along to the given nameserver
			response = sendPacket(nameserver, data)
			# Parse the response
			# Will either continue with the required queries or send the final response back to returnAddr
			parseResponse(response, hostname, nameserver)
	# Not daemon, display output directly
	else:
		# Given both the hostname to locate and the nameserver to query
		hostname = args[0]
		nameserver = args[1]

		# Build the packet
		packet = buildPacket(hostname, TYPE['A'])
		# Send the packet
		response = sendPacket(nameserver, packet)
		# Parse the response
		parseResponse(response, hostname, nameserver)


# __name__ will be '__main__' if this code is being run directly (i.e. 'python dug.py')
# If so, execute normally. Otherwise, this code is being imported into another module
if __name__ == '__main__':
	main()