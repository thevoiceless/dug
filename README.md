dug
=====
`dug` is a stripped-down Python implementation of `dig`. When run normally, the program queries a given nameserver about a given hostname and prints the result. When run as a daemon, the program listens for data on a specific port, forwards that data to a given nameserver, and then returns the answer. If the debug flag is given, the program will print out each question and all of the resource records in each response.


Notes
-----

### Running normally
* `dug` currently only knows how to handle A, NS, and CNAME requests/records. AAAA records are recognized but not acted upon.
* The program assumes that only one question was asked in each datagram.
* If no A records are returned but NS records are included, the program assumes that the IP addresses of those nameservers are also included.

### Running as a daemon
* This mode was designed to receive DNS datagrams created by `dig`, send them, and then hand the response back to `dig`. It's not really good for anything else. The listening port is specified by the `MY_PORT` variable in `dug.py`
* There is no threading or coordination of datagram IDs, so there will probably be issues if the program receives multiple packets at the same time when running as a daemon.


Usage
-----
`python dug.py [-d] hostname nameserver` to run normally  
`python dug.py [-d] -f nameserver` to run as a daemon


Dependencies
-----
* Python 2.4 or later