#!/usr/local/bin/python3

import sys, collections
import pprint
import ipaddress
import dns.query, dns.zone


debug = warning = False
# DNS server to AXFR from
dns_server = 'ns1-int.scea.com'

zone_name = []

# a dict of lists of all the forward (A, AAAA) records
forward_records = collections.defaultdict(list)
# a dict of lists of all the reverse (PTR) records
reverse_records = []

usage = 'Usage: dns-purist [--debug] [--warning] zonename or zonefile.zone...'

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


##main:
# command line args
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

debug = True
# now, let's see if we have a valid forward_records dict
for fqdn in forward_records.keys():
   if (debug):
      print('forward <%s> address ' % fqdn, end="")
   addr_count = len(forward_records[fqdn])
   for addr in forward_records[fqdn] :
      if (debug):
         print('%s' % addr, end="")
         addr_count-= 1
         if (addr_count < 1):
            print()
         else:
            print(', ', end="")



sys.exit()

# find, open file
# foreach line, check for valid IP address, look up PTR record, fail as needed
with open(filename) as f:
   for line in f:
      line = line.strip()
##TODO need to check for malformed IP addresses and blank lines here
      if (line == ''):
         continue
      try:
         isitanaddr = ipaddress.ip_address(line)
      except ValueError:
         print('ERROR: %s :invalid IP address' % line)
         continue
      revname = dns.reversename.from_address(line)
      if (debug):
         print('line <%s>, REVNAME %s' % (line, revname))
      try:
         answers = dns.resolver.query(revname, 'PTR')
      except dns.resolver.NXDOMAIN :
         print('ERROR: %s: no PTR' % line)
         continue
      except dns.exception.Timeout :
        print('ERROR: %s: Timeout' % line)
        continue
      except Exception as exception:
         print('ERROR: %s: UNKNOWN resolver error' % line)
         print(' exc: %s' % type(exception).__name__ )
         continue
      for rdata in answers:
         print('OK: %s : <%s>' % (line,rdata))
      time.sleep(throttle)
