#!/usr/bin/env python3

# Import the Dumper class
from ipdump import Dumper

# Create a Dumper with the target "imap.gmail.com"
dumper = Dumper("imap.gmail.com")

# Print status message
print("Open Ports: ", end="")

# For each open port, print it to the console
dumper.get_open_ports(start=1, end=1000, callback=lambda portinfo: print(portinfo.port, end=" "), timeout=1)

# Print a newline, to write PS1 on a newline
print("")
