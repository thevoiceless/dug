#! /usr/bin/env python

# The machine this was designed to run on only has Python 2.4.3, so optparse is used instead of argparse
import optparse, random, sys


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

	return ((numBits - len(bStr)) * '0') + bStr


def buildPacket(hostname):
	header = ''
	# 16-bit identifier for the query (0 to 65535)
	header += d2b(random.randint(0, 65535), 16)
	# One bit specifying that this is a query (0)
	header += d2b(0, 1)
	# Four-bit opcode specifying this is a standard query (0000)
	header += d2b(0, 4)
	# One bit for responses that give an authoritative answer (doesn't apply here)
	header += d2b(0, 1)
	# One bit indicating whether or not the message was truncated (it won't be)
	header += d2b(0, 1)
	# One bit indicating if recursion is desired (no recursion desired)
	header += d2b(0, 1)
	# One bit used in responses to indicate that recursion is available (doesn't apply here)
	header += d2b(0, 1)
	# 3 bits reserved for future use, must be zero in all queries and responses
	header += d2b(0, 3)
	# 4-bit response code (doesn't matter here)
	header += d2b(0, 4)
	# Unsigned 16-bit integer specifying the number of questions (1)
	header += d2b(1, 16)
	# Unsigned 16-bit integer specifying the number of resource records (doesn't apply here)
	header += d2b(0, 16)
	# Unsigned 16-bit integer specifying the number of name server records (doesn't apply here)
	header += d2b(0, 16)
	# Unsigned 16-bit integer specifying the number of additional records (doesn't apply here)
	header += d2b(0, 16)

	for index, bit in enumerate(header):
		if index % 16 == 0:
			sys.stdout.write('\n')
		else:
			sys.stdout.write(bit)




def main():
	# Parse command-line arguments
	parser = optparse.OptionParser(description = 'Basic dig implementation using Python',
		usage = "usage: %prog hostname nameserver")

	(options, args) = parser.parse_args()
	if len(args) != 2:
		parser.error("Wrong number of arguments")
	print options
	print args

	hostname = args[0]
	nameserver = args[1]

	# Build the packet
	buildPacket(hostname)


# __name__ will be '__main__' if this code is being run directly (i.e. 'python dug.py')
# If so, execute normally. Otherwise, this code is being imported into another module
if __name__ == '__main__':
	main()