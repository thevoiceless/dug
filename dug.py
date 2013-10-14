#! /usr/bin/env python

# The machine this was designed to run on only had Python 2.4.3, so optparse is used instead of argparse
import optparse


def main():
	# Parse command-line arguments
	parser = optparse.OptionParser(description = 'Basic dig implementation using Python',
		usage = "usage: %prog hostname nameserver")

	(options, args) = parser.parse_args()

	print options
	print args


# __name__ will be '__main__' if this code is being run directly (i.e. 'python dug.py')
# If so, execute normally. Otherwise, this code is being imported into another module
if __name__ == '__main__':
	main()