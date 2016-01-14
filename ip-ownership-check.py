#!/usr/local/bin/python3
import sys, collections
import pprint
import ipaddress
##import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

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
    invalid_range_count = 0
    f = open(range_file, 'r')
    for l in f:
        l = l.rstrip()
# TODO validate that the range is properly formatted
        try:
            address = ipaddress.IPv4Network(l)
            valid_address_ranges.append(address)
            valid_range_count += 1
        except ValueError:
            print('VALUEERROR: %s' % l)
            invalid_range_count += 1
    print('%d valid ranges loaded, %d invalid ranges ignored' % (valid_range_count, invalid_range_count))


def load_suspect_ips(ip_file):
    address_count = 0
    f = open(ip_file, 'r')
    for l in f:
        l = l.rstrip()
# validate that the IP address is properly formatted
        suspect_ip_list.append(l)
        address_count += 1
    print('%d valid addresses loaded' % address_count)

def addr_in_range(ip_addr, ip_range_list):
# is the given IP address contained in any of the loaded ranges?
    for ip_range in ip_range_list:
        #TODO detect and handle ipv6
        if (ipaddress.IPv4Address(ip_addr) in ip_range):
            return True
    return False



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

## TODO - there are two use cases:
## 1. find IP addresses that are NOT in any of the loaded ranges (data validation)
## -OR-
## 2. verify that an IP address is in one of the ranges (extract target lists for a specific site from a larger list of IPs
## which one am I solving here?!?!?
## for now, emit them with diff prefixes, and use grep to pick the one you want :-(

    for ip_addr in suspect_ip_list:
        if (not addr_in_range(ip_addr, valid_address_ranges)):
            print('UNKNOWN %s' % ip_addr)
        else:
            print('VALID %s' % ip_addr)
    
    sys.exit()


if __name__ == '__main__' :
   main()
