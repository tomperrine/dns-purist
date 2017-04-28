#!/usr/local/bin/python3

import sys, collections
import pprint
import ipaddress
import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

debug = False
# DNS server to AXFR from
dns_server = 'ns1-int.scea.com'

zone_name = []

# a dict of lists of all the forward (A, AAAA) records
forward_records = collections.defaultdict(list)
# a dict of lists of all the reverse (PTR) records
reverse_records = []

usage = 'Usage: dns-purist [--debug] [--warning] zonename or zonefile.zone...'

def ping(host):
    """
    Returns True if host responds to a ping request
    """
    import os, platform

    # Ping parameters as function of OS
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1 >/dev/null"

    # Ping
    return os.system("ping " + ping_str + " " + host ) == 0

def strip_end(text, suffix):
    if not text.endswith(suffix):
        return text
    return text[:len(text)-len(suffix)]

def load_forward_records(zone, record_type):
## modifies global forward_records[] !!!
   if ( (record_type != 'A') and (record_type != 'AAAA')):
      print('load_forward_records: invalid record type %s' % record_type)
      sys.exit()
   for (fqdn, ttl, rdata) in zone.iterate_rdatas(record_type):
      # this is already a FQDN since we used relativize=False
      #special case to get rid of the self-reference record
      if (not fqdn):
         continue
      if (debug):
         print ('fqdn <%s> zone <%s>' % (fqdn, zone))
      addr = ipaddress.ip_address(rdata.address)
      if (debug):
         print ('fqdn %s IP %s' % (fqdn, str(addr)))
      # append the address we just found to the list of addresses for this FQDN
      forward_records[fqdn].append(addr)

#check that the address for the FQDN:
# 1. is a valid IP address
# 2. has a PTR record
# 3. the PTR record matches the given FQDN (this may be wrong)
# 4. TODO the found FQDN has at least one A/AAAA that matches the original address
# returns True if valid, False otherwise
def check_reverse(fqdn, address):
   # is this a valid IP address?
   if ( (not fqdn) or (not address)):
      print('check_reverse: bad arguments %s %s' % (fqdn, address))
      sys.exit()
   try:
      isitanaddr = ipaddress.ip_address(address)
   except ValueError:
      print('ERROR: %s :invalid IP address' % address)
      return False
   revname = dns.reversename.from_address(address)
   if (debug):
      print('address<%s>, revname %s' % (address, revname))
      # is there a valid PTR for the address
   try:
      answers = dns.resolver.query(revname, 'PTR')
   except dns.resolver.NXDOMAIN :
#      print('ERROR: %s: no PTR' % address)
      return False
   except dns.exception.Timeout :
      print('ERROR: %s: Timeout' % address)
      return False
   except Exception as exception:
      print('ERROR: %s: UNKNOWN resolver error' % address)
      print(' exc: %s' % type(exception).__name__ )
      return False
   # at this point there is at least one PTR record
   for rdata in answers:
      if (str(rdata) == str(fqdn)):
##         print('check_reverse: MATCH %s %s %s' % (address, rdata, fqdn))
         return True # found at least one matching name
   # or no matches found...
##   print('check_reverse: NOMATCH %s %s %s' % (address, rdata, fqdn))
   return False


def main():
   debug = warning = False

   if len(sys.argv) < 2:
      print(usage)
      sys.exit()

   for arg in sys.argv[1:]:
      if (arg == '--debug') :
         debug = True
      elif (arg == '--warning') :
         warning = True
      else :
         zone_name.append(arg)

   if (debug):
      print('debug %s, warning %s, zone_name(s) %s' % (debug, warning, zone_name))

    # go read all the zones via AXFR or zone file, depending on the argument
   for zone in zone_name :
      print('loading %s ...' % zone)
      if (zone.endswith('.zone')):
         origin = strip_end(zone, '.zone')
         z = dns.zone.from_file(zone, origin, relativize=False)
      else:
         try:
            z = dns.zone.from_xfr(dns.query.xfr('ns1-int.scea.com', zone), relativize=False)
         except dns.exception.FormError :
            print('dns.exception.FormError: No answer or RRset not for qname')
            continue
      load_forward_records(z, 'A')
      load_forward_records(z, 'AAAA')

   # walk all the forward records and do the following tests
   # 1. has a matching PTR
   # 2. is pingable
   for fqdn in forward_records.keys():
      if (debug):
         print('forward <%s> address ' % fqdn, end="")
         addr_count = len(forward_records[fqdn])
      for addr in forward_records[fqdn] :
         # addr is an IPV4Address, is easier to check as a string
         if (check_reverse(fqdn, str(addr))):
            # found at least one valid PTR that points to this name
            pass
#            print('PTROK: host %s has A %s, found matching PTR' % (fqdn, addr))
         else:
            print('NOPTR: host %s has A %s, no matching PTR records found' % (fqdn, addr))
         if (ping(str(fqdn))):
            print('PING: host %s %s responds to ping' % (fqdn, addr))
         else:
            print('NOPING: host %s %s no repsonse to ping' % (fqdn, addr))
         if (debug):
            print('%s' % addr, end="")
            addr_count-= 1
            if (addr_count < 1):
               print()
            else:
               print(', ', end="")



if __name__ == '__main__' :
   main()
