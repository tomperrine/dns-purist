#!/usr/local/bin/python3
import sys, collections
import pprint
import ipaddress
import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

# Takes two inputs:
# 1. a list of IP address ranges (subnet/CIDR notation OK) that are "expected" - eg that you should have hosts in, for example
# 2. a list of IP addresses to check
#
# Verifies that all IP addresses in #2 are in #1
# emit error message for all IP addresses not in know expected ranges

# a list of valid address blocks
valid_address_ranges = []

# a list of IP address to test (string values)
suspect_ip_list = []


usage = 'Usage: ip-ownership-check.py valid-ip-ranges ip-addresses-to-check'
# valid-ip-ranges file can be a flat file (for now), or eventually an XLS - use suffix to decide?
# ip-addresses-to-check is a flat file, one IP per line (add XLS support in the future?)

def load_valid_ranges(range_file):
# load a file of network ranges
# for now, this must be address blocks in CIDR notation, one per line
# eventually, we'll be able to take XLS
    valid_range_count = 0
    f = open(range_file, 'r')
    for l in f:
        l = l.rstrip()
        print('<%s>' % l)
        valid_address_ranges.append(l)
        valid_range_count += 1
    print('%d valid ranges added' % valid_range_count)


def load_suspect_ips(ip_file):
    b = 2

def main():


    if len(sys.argv) < 3:
        print(usage)
        sys.exit()

    valid_ranges_file = sys.argv[1]
    ips_to_check_file = sys.argv[2]

# load valid IP ranges
    load_valid_ranges(valid_ranges_file)


# load IPs to check for easier iteration and performance, makes it easier to handle XLS in future
    load_suspect_ips(ips_to_check_file)

# TEST
    # foreach IP to check
    #     is it in any of the ranges?
    
    sys.exit()


if __name__ == '__main__' :
   main()
