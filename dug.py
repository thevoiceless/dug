#! /usr/bin/env python

# The machine this was designed to run on only has Python 2.4.3, so optparse is used instead of argparse
import optparse, random, struct


DEBUG = True


# Build the DNS datagram
# Uses the struct module to convert values to their byte representation
def buildPacket(hostname):
	# Build the header
	header = ''

	# 16-bit identifier for the query (0 to 65535)
	identifier = random.randint(0, 65535)

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
	qtype = 1
	questionSegment += struct.pack("!H", qtype)

	# Two-byte field specifying query class (IN = 1)
	qclass = 1
	questionSegment += struct.pack("!H", qclass)

	if DEBUG:
		print "%-8s %s" % ("Bytes:", repr(header + questionSegment))
		print "%-8s %s" % ("Hex:", ''.join([ "%02x " % ord(x) for x in header + questionSegment ]).strip())



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
	buildPacket(hostname)


# __name__ will be '__main__' if this code is being run directly (i.e. 'python dug.py')
# If so, execute normally. Otherwise, this code is being imported into another module
if __name__ == '__main__':
	main()