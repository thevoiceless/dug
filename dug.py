#! /usr/bin/env python

# This script is designed to run in Python 2.4.3, meaning:
#   optparse instead of argparse
#   struct instead of bytes
#   d2b() instead of bin()
#   No ternary statement
#   Old string formatting

import optparse, random, struct, socket


DEBUG = True
PORT = 53
RECV_BUF = 1024
TYPE = { 'A': 1,
         'NS': 2,
         'CNAME': 5 }
CLASS_IN = 1
RCODE = { 0: 'No errors',
          1: 'Format error - The name server was unable to interpret the query',
          2: 'Server failure - The name server was unable to process this query due to a problem with the name server',
          # Only meaningful for responses from authoritative name servers
          3: 'Name error - The domain name referenced in the query does not exist',
          4: 'Not Implemented - The name server does not support the requested kind of query',
          5: 'Refused - The name server refuses to perform the specified operation for policy reasons' }


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


# Parse the labels from byteString and add the result to returnText
def parseLabels(returnText, byteString, orig = None):
	label = ''
	print "in function, byteString is", repr(byteString)
	while True:
		checkPointer = d2b(struct.unpack("!H", byteString[:2])[0], 16)
		if checkPointer[:2] == '11':
			# print "Next part might be a pointer:", repr(byteString)
			byteString = byteString[2:]
			offset = int(checkPointer[2:], 2)
			# print "offset", offset, "=", repr(orig[offset:])
			plabel, _ = parseLabels(label, orig[offset:], orig)
			return label + '.' + plabel, byteString
		else:
			qlen, byteString = struct.unpack("!B", byteString[:1])[0], byteString[1:]
			if qlen == 0:
				break
			if len(label) > 0:
				label += '.' + byteString[:qlen]
			else:
				label += byteString[:qlen]
			# print label
			# print repr(byteString)
			byteString = byteString[qlen:]
	return label, byteString


# Build the DNS datagram
# Uses the struct module to convert values to their byte representation
def buildPacket(hostname):
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

	# Two-byte field specifying query type (A = 1)
	qtype = TYPE['A']
	questionSegment += struct.pack("!H", qtype)

	# Two-byte field specifying query class (IN = 1)
	qclass = CLASS_IN
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


def parseResponse(response):
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
	questions = ''
	# Loop qdcount times
	for q in range(qdcount):
		# List each question on its own line
		if len(questions) > 0:
			questions += '\n'

		# Name
		questions, response = parseLabels(questions, response)

		# Type
		qtype, response = struct.unpack("!H", response[:2])[0], response[2:]
		if qtype == TYPE['A']:
			questions += ', Type A'
		elif qtype == TYPE['NS']:
			questions += ', Type NS'
		elif qtype == TYPE['CNAME']:
			questions += ', Type CNAME'

		# Class
		qclass, response = struct.unpack("!H", response[:2])[0], response[2:]
		if qclass == CLASS_IN:
			questions += ', Class IN'
	
	if DEBUG:
		print "Questions:", questions

	print "before answers, response is", repr(response)
	# Parse answers
	answers = ''
	# Loop ancount times
	for a in range(ancount):
		# List each answer on its own line
		if len(answers) > 0:
			answers += '\n'

		# Name, variable length
		checkName = d2b(struct.unpack("!H", response[:2])[0])
		label = ''
		# If the binary representation of first two bytes starts with '11', name points to a label
		# if checkName[:2] == '11':
		# 	# Consume the two bytes and determine the offset of the name within the response
		# 	response = response[2:]
		# 	offset = int(checkName[2:], 2)

		# 	# The question section has been consumed, so refer to the original response string 
		# 	offsetResponse = origResponse[offset:]
		# 	label, r = parseLabels(label, offsetResponse, origResponse)
		# 	print "r is", repr(r)
		# 	print "response is", repr(response)
		# # Otherwise, name is a label
		# else:
		# 	if DEBUG:
		# 		print "Name is a label"
		# 	print repr(response)
		# 	label, response = parseLabels(label, response, origResponse)
		label, response = parseLabels(label, response, origResponse)

		answers += label
				
		# if DEBUG:
		# 	print "First two bits of name are set, pointer to offset", offset, "=", label

		# Type of the RDATA field
		rtype, response = struct.unpack("!H", response[:2])[0], response[2:]
		print "type is", rtype
		if rtype == TYPE['A']:
			answers += ', Type A'
		elif rtype == TYPE['NS']:
			answers += ', Type NS'
		elif rtype == TYPE['CNAME']:
			answers += ', Type CNAME'

		# Class of the RDATA field
		rclass, response = struct.unpack("!H", response[:2])[0], response[2:]
		print "class is", rclass
		if rclass == CLASS_IN:
			answers += ', Class IN'

		# Unsigned 32-bit value specifying the TTL in seconds
		ttl, response = struct.unpack("!I", response[:4])[0], response[4:]
		answers += ', TTL ' + str(ttl)
		print "ttl is", ttl

		# Unsigned 16-bit value specifying the length of the RDATA field
		rdlen, response = struct.unpack("!H", response[:2])[0], response[2:]

		# Variable-length data (depending on type of record) for the resource
		if rtype == TYPE['A']:
			# A-type records return an IP address as a 32-bit unsigned value
			try:
				ip = socket.inet_ntoa(response)
				answers += ', IP ' + ip
			except socket.error:
				print "Error: Incorrect format for A-type RDATA"
		elif rtype == TYPE['NS']:
			pass

	if ancount:
		print "Answers:", answers
	else:
		print "No answers"


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
	packet = buildPacket(hostname)
	# Send the packet
	response = sendPacket(nameserver, packet)
	# Parse the response
	parseResponse(response)


# __name__ will be '__main__' if this code is being run directly (i.e. 'python dug.py')
# If so, execute normally. Otherwise, this code is being imported into another module
if __name__ == '__main__':
	main()