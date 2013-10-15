#! /usr/bin/env python

# The machine this was designed to run on only has Python 2.4.3, hence the use of older modules
import optparse, random, struct, socket


DEBUG = True
PORT = 53
RECV_BUF = 1024
TYPE = { 'A': 1,
         'NS': 2,
         'CNAME': 5 }
CLASS_IN = 1


# No bin() in 2.4
# Convert unsigned int n to binary representation that is numBits long
# Most credit goes to http://stackoverflow.com/a/1519418/1693087
def d2b(n, numBits):
	bStr = ''
	if n < 0:
		raise ValueError, "must be a positive integer"
	if n > (2**numBits - 1):
		raise ValueError, "not enough bits to represent " + str(n)
	if n == 0:
		return '0' * numBits
	while n > 0:
		bStr = str(n % 2) + bStr
		n = n >> 1
	return bStr.zfill(numBits)


# Build the DNS datagram
# Uses the struct module to convert values to their byte representation
def buildPacket(hostname):
	# Build the header
	header = ''

	# 16-bit identifier for the query (0 to 65535)
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

	# Unsigned 16-bit integer specifying the number of questions (1)
	qdcount = 1
	header += struct.pack("!H", qdcount)

	# Unsigned 16-bit integer specifying the number of resource records (doesn't apply here)
	ancount = 0
	header += struct.pack("!H", ancount)

	# Unsigned 16-bit integer specifying the number of name server records (doesn't apply here)
	nscount = 0
	header += struct.pack("!H", nscount)

	# Unsigned 16-bit integer specifying the number of additional records (doesn't apply here)
	arcount = 0
	header += struct.pack("!H", arcount)

	# Build the question segment
	questionSegment = ''

	# A sequence of labels, where each label consists of a length byte followed by that number of bytes
	for piece in hostname.split('.'):
		# No part of the domain name may exceed the max value for a byte (255)
		if len(piece) > 255:
			raise ValueError, "part of the domain name exceeds the maximum allowed length (255)"
		# Length byte, "!B" identifier indicates network-formatted (big-endian) unsigned char (1 byte)
		questionSegment += struct.pack("!B", len(piece))
		# The bytes themselves
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
	print "Creating socket"
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print "Sending packet"
	sock.sendto(packet, (nameserver, PORT))
	print "Receiving response"
	data, addr = sock.recvfrom(RECV_BUF)
	print "Received:", repr(data)
	return data


def parseResponse(response):
	# Parse header
	# Identifier
	(identifier,), response = struct.unpack("!H", response[:2]), response[2:]
	# Flags
	(flags,), response = struct.unpack("!H", response[:2]), response[2:]
	flags = d2b(flags, 16)
	qr, opcode, aa, tc, rd, ra, z, rc = flags[0], flags[1:5], flags[5], flags[6], flags[7], flags[8], flags[9:12], flags[12:]
	# Number of questions
	(qdcount,), response = struct.unpack("!H", response[:2]), response[2:]
	# Number of answers
	(ancount,), response = struct.unpack("!H", response[:2]), response[2:]
	# Number of resource records
	(nscount,), response = struct.unpack("!H", response[:2]), response[2:]
	# Number of additional records
	(arcount,), response = struct.unpack("!H", response[:2]), response[2:]

	# Parse question
	question = ''
	# Name
	while True:
		(qlen,), response = struct.unpack("!B", response[:1]), response[1:]
		if qlen == 0:
			break
		question += '.' + response[:qlen] if len(question) > 0 else response[:qlen]
		response = response[qlen:]
	# Type
	(qtype,), response = struct.unpack("!H", response[:2]), response[:2]
	if qtype == TYPE['A']:
		question += ', Type A'
	elif qtype == TYPE['NS']:
		pass
	elif qtype == TYPE['CNAME']:
		pass
	# Class
	(qclass,), response = struct.unpack("!H", response[:2]), response[:2]
	if qclass == CLASS_IN:
		question += ', Class IN'
	print question

	# Parse answer



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