#! /usr/bin/env python

import argparse

parser = argparse.ArgumentParser(description = 'Basic dig implementation using Python')
parser.add_argument('hostname', help = 'Name of the host to ask about')
parser.add_argument('nameserver', help = 'IP address of the nameserver to query')
