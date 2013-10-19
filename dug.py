#! /usr/bin/env python

# This script is designed to run in Python 2.4.3, meaning:
#   optparse instead of argparse
#   struct instead of bytes
#   d2b() instead of bin()
#   No ternary statement
#   Old string formatting

import optparse, random, struct, socket, sys


DEBUG = True
PORT = 53
RECV_BUF = 1024
ROOT_E = '192.203.230.10'
# Map types to ints and ints to types
TYPE = { 'A': 1,
         'NS': 2,
         'CNAME': 5 }
TYPE_NAMES = { 1: 'A',
               2: 'NS',
               5: 'CNAME' }
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


def printQuestion(question):
	print question[QNAME], CLASS_NAMES[question[QCLASS]], TYPE_NAMES[question[QTYPE]]


def printAnswer(answer):
	print answer[ANAME], answer[ATTL], CLASS_NAMES[answer[ACLASS]],
	try:
		print TYPE_NAMES[answer[ATYPE]],
	except KeyError:
		print "type", answer[ATYPE],
	if len(answer) == 6:
		print answer[ADATA]
	else:
		print


# Convert unsigned int n to binary representation, optionally specify number of bits
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


# Parse the labels from byteString
# The orig parameter is not needed when parsing labels in question sections, as those shouldn't have pointers
def parseLabel(byteString, orig = None):
	label = ''
	while True:
		# If the binary representation of first two bytes starts with '11', name points to a label
		checkPointer = d2b(struct.unpack("!H", byteString[:2])[0], 16)
		if checkPointer[:2] == '11':
			if not orig:
				raise ValueError, "must pass the original response to parseLabel"
			# Consume the two bytes and determine the offset of the name within the response
			byteString = byteString[2:]
			offset = int(checkPointer[2:], 2)
			# The question section has been consumed, so refer to the original response string
			plabel, _ = parseLabel(orig[offset:], orig)
			if len(label) > 0:
				label += '.' + plabel
			else:
				label += plabel
			# Pointers terminate labels, so break and return
			break
		# Otherwise, name is a label, read it normally
		else:
			qlen, byteString = struct.unpack("!B", byteString[:1])[0], byteString[1:]
			if qlen == 0:
				break
			if len(label) > 0:
				label += '.' + byteString[:qlen]
			else:
				label += byteString[:qlen]
			byteString = byteString[qlen:]
	return label, byteString


def parseRRs(outputList, recordCount, response, origResponse):
	# Loop recordCount times
	# print "loop", recordCount, "times"
	for rec in range(recordCount):
		# print "----- RR", rec+1
		# [name, rtype, rclass, ttl, rdlen, rdata]
		outputList.append([])

		# Name, variable length
		name, response = parseLabel(response, origResponse)
		outputList[rec].append(name)
		# print "name", name

		# Type of the RDATA field
		rtype, response = struct.unpack("!H", response[:2])[0], response[2:]
		outputList[rec].append(rtype)
		# print "type", rtype

		# Class of the RDATA field
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

		# Variable-length data (depending on type of record) for the resource
		if rtype == TYPE['A']:
			# A-type records return an IP address as a 32-bit unsigned value
			try:
				ip = socket.inet_ntoa(response[:4])
				# print "ip", ip
				outputList[rec].append(ip)
			except socket.error:
				print "Error: Incorrect format for A-type RDATA"
				print outputList
				print repr(response)
				sys.exit(1)
		elif rtype == TYPE['NS'] or rtype == TYPE['CNAME']:
			name, _ = parseLabel(response, origResponse)
			# print "name", name
			outputList[rec].append(name)
		# Consume rdlen bytes of data
		response = response[rdlen:]

	return response


# Build the DNS datagram
# Uses the struct module to convert values to their byte representation
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

	if DEBUG:
		print "%-8s %s" % ("Bytes:", repr(header + questionSegment))
		print "%-8s %s" % ("Hex:", ''.join(["%02x " % ord(x) for x in header + questionSegment]).strip())

	return header + questionSegment


def sendPacket(nameserver, packet):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto(packet, (nameserver, PORT))
	print "Packet sent"
	data, addr = sock.recvfrom(RECV_BUF)
	print "Received:", repr(data)
	return data


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

	if DEBUG:
		print "ID:", identifier
		print "Return code:", int(rc, 2), "(" + RCODE[int(rc, 2)] + ")"
		print "Truncated:", 
		if int(tc):
			print 'Yes'
		else:
			print 'No'
		print "Answer RRs:", ancount
		print "Authoritative:",
		if int(aa):
			print 'Yes'
		else:
			print 'No'
		print "Authority RRs:", nscount
		print "Additional RRs:", arcount

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
	
	if DEBUG:
		print "Questions:"
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

	if DEBUG:
		if ancount:
			print "Answers:"
			for answer in answers:
				printAnswer(answer)
		else:
			print "No answers"

		if nscount:
			print "Authority:"
			for auth in authorities:
				printAnswer(auth)
		else:
			print "No authority RRs"

		if arcount:
			print "Additional:"
			for add in additionals:
				printAnswer(add)
		else:
			print "No additional RRs"

	# For A-type requests, check for answers
	if qtype == TYPE['A']:
		# Display any answers that are present
		if ancount:
			if int(aa):
				print "Authoritative:"
			else:
				print "Non-authoritative:"
			for answer in answers:
				if answer[ATYPE] == TYPE['CNAME']:
					# If the only answer is a CNAME alias for another hostname, we need the A record for the alias
					# There's a good chance this will mess up the output, but I haven't tested it
					if ancount == 1:
						# Build the packet
						packet = buildPacket(answer[ADATA], TYPE['A'])
						# Send the packet
						response = sendPacket(nameserver, packet)
						# Parse the response
						parseResponse(response, answer[ADATA], nameserver)
						break
					# Otherwise, we'll just show the other answers
					else:
						continue
				print answer[ADATA]
		# Otherwise, make an NS query to determine who we should be asking 
		else:
			print "Send NS request"
			# Build the packet
			packet = buildPacket(hostname, TYPE['NS'])
			# Send the packet
			response = sendPacket(nameserver, packet)
			# Parse the response
			parseResponse(response, hostname, nameserver)

	# For NS-type requests, check the authority section
	# If no NS records are returned, query the root E nameserver (after that, records should always be returned)
	elif qtype == TYPE['NS']:
		if nscount:
			# Assume that if a nameserver is known, so is its IP
			pickNS = authorities[0][5]
			nsIP = ''
			for a in additionals:
				if a[ANAME] == pickNS and a[ATYPE] == TYPE['A']:
					nsIP = a[ADATA]
			print "Now query", pickNS, "=", nsIP
			packet = buildPacket(hostname, TYPE['A'])
			# Send the packet
			response = sendPacket(nsIP, packet)
			# Parse the response
			parseResponse(response, hostname, nsIP)
		else:
			print "Failure - No NS records"
			print "Ask root nameserver"
			# Build the packet
			packet = buildPacket(hostname, TYPE['NS'])
			# Send the packet
			response = sendPacket(ROOT_E, packet)
			# Parse the response
			parseResponse(response, hostname, ROOT_E)

	# TODO: Refactor repeated building/sending/parsing into single block right here?
	# TODO: If so, would need to halt execution after printing answers above


def main():
	# Parse command-line arguments
	parser = optparse.OptionParser(description = 'Basic dig implementation using Python',
		usage = "usage: %prog hostname nameserver")

	(options, args) = parser.parse_args()
	if len(args) != 2:
		parser.error("Wrong number of arguments")
	if DEBUG:
		print "%-8s %s" % ("Options:", options)
		print "%-8s %s" % ("Args:", args)

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