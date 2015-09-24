#!/usr/local/bin/python3

import sys, pprint
import ipaddress
import dns.query, dns.reversename, dns.resolver

debug = warning = False
usage = 'Usage: dns-purist [--debug] [--warning] filename-of-ips'

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
      filename = arg

if (debug):
   print('debug %s, warning %s, filename %s' % (debug, warning, filename))

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
      except dns.resolver.NXDOMAIN:
         print('ERROR: %s: no PTR' % line)
         continue
      for rdata in answers:
         print('OK: %s : <%s>' % (line,rdata))
