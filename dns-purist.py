#!/usr/local/bin/python3

import sys, collections
import pprint
import ipaddress
import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

debug = True
trace = False
no_dns= False
force_ptr_lookups = False

# DNS server to AXFR from
dns_server = 'ns1-int.scea.com'
zone_suffix = '.zone'
revzone_suffix = '.revzone'

zone_name = []

# a dict of lists of all the forward (A, AAAA) records
forward_records = collections.defaultdict(list)
# a dict of lists of all the reverse (PTR) records
reverse_records = collections.defaultdict(list)


usage = 'Usage: dns-purist [--trace] [--debug] [--warning] [--ping] [--no_dns] [--force_ptr_lookups] targetzone, zonefile.zone, zonefile.revzone'

def ping(address):
    """
    Returns True if host (defined by address) responds to a ping request
    """
    import os, platform

    # Is it v4 or v6? Set initial guess for ping command here
    try:
        addr_obj = ipaddress.ip_address(address)
    except ValueError:
        print('ERROR: %s :invalid IP address' % address)
        return False
    if (addr_obj.version == 4):
        ping_command = 'ping'
    elif (addr_obj == 6):
        ping_command = 'ping6'
    else:
        print('ERROR: %s :invalid IP address version' % addr_obj.version)
        return False

    # Ping parameters as function of OS
    p = platform.system().lower()
    if (p =="windows") :
        ping_command = 'ping' #uses same command for v4 and v6, but
        # TODO Does Windows need a -6 or -4 argument if given an address???
        ping_str = "-n 1"
        redirect = ''
    else:
        ping_str = "-c 1"
        redirect = ' >/dev/null'

    # Ping
    return (os.system("ping " + ping_str + " " + address + " " + redirect) == 0)


def strip_end(text, suffix):
    if not text.endswith(suffix):
        return text
    return text[:len(text)-len(suffix)]

def load_forward_records(zone, record_type, zone_type):
    global debug, trace, no_dns, warning, doping, force_ptr_lookups
## modifies global forward_records[] !!!
    record_count = 0
    if ( (record_type != 'A') and (record_type != 'AAAA')):
        print('load_forward_records: invalid record type %s' % record_type)
        sys.exit()
   # search through the zone file looking for A/AAAA
    for (fqdn, ttl, rdata) in zone.iterate_rdatas(record_type):
        # this is already a FQDN since we used relativize=False
        #special case to get rid of the self-reference record
        if (not fqdn):
            continue
        if (debug):
            print ('fqdn <%s> zone <%s>' % (fqdn, zone))
      # should not see any forward records, emit warning
        if (zone_type != 'forward'):
            print()
            print('BADREC: forward record %s/%s found in reverse zone' % (fqdn,rdata.address))
            continue
        ## TODO check for fully-qualified names that don't match the zone name??
        ## Is this even possible with "no relativize"??
        addr = ipaddress.ip_address(rdata.address)

        if (debug):
            print ('fqdn %s IP %s' % (fqdn, str(addr)))
        # append the address we just found to the list of addresses for this FQDN
        forward_records[fqdn].append(addr)
        record_count += 1
    return record_count


def load_reverse_records(zone, record_type, zone_type):
    global debug, trace, no_dns, warning, doping, force_ptr_lookups
## modifies global reverse_records  
    record_count = 0
    if (record_type != 'PTR'):
      print('load_reverse_records: invalid record type %s' % record_type)
      sys.exit()
    for (qname, ttl, rdata) in zone.iterate_rdatas(record_type):
        # this is already a full address since we used relativize=False
        if (debug):
            print ('load_reverse_records: qname %s target %s' % (qname, str(rdata.target)))
        if (zone_type != 'reverse'):
            print()
            print('BADREC: reverse record %s/%s found in forward zone' % (qname,rdata.target))
            continue
       # append the target we just found to the list of targets for this qname
        reverse_records[qname].append(rdata.target)
        record_count += 1
    return record_count

def check_reverse_by_dns(revname):
# returns all answers
    global debug, trace, no_dns, warning, doping, force_ptr_lookups
    if (trace):
        print('check_reverse_by_dns')
    try:
        answers = dns.resolver.query(revname, 'PTR')
    except dns.resolver.NXDOMAIN :
        #      print('ERROR: %s: no PTR' % address)
        return ""
    except dns.exception.Timeout :
        print('ERROR: %s: DNS Timeout' % revname)
        return ""
    except Exception as exception:
        print('ERROR: %s: UNKNOWN resolver error' % revname)
        print(' exc: %s' % type(exception).__name__ )
        return ""
    return answers


#check that the address for the FQDN:
# 1. is a valid IP address
# 2. has a PTR record
# 3. the PTR record matches the given FQDN (this may be wrong if there are multiple A/AAAA records)
# 4. TODO the found FQDN has at least one A/AAAA that matches the original address
# returns True if valid, False otherwise
def check_reverse(fqdn, address, force_query):
    global debug, trace, no_dns, warning, doping, force_ptr_lookups

    if (trace):
        print('check_reverse: %s %s %s' % (fqdn, address, force_query))

   # is this a valid IP address?
    if ( (not fqdn) or (not address)):
        print('check_reverse: bad arguments %s %s' % (fqdn, address))
        sys.exit()
    try:
        isitanaddr = ipaddress.ip_address(address)
    except ValueError:
        print('ERROR: %s :invalid IP address' % address)
        return False

   # get the reverse form of the IP address
    revname = dns.reversename.from_address(address)
    if (debug):
        print('address <%s>, revname %s' % (address, revname))

   # first, look and see if we've already loaded a reverse record
   # records are only loaded/cached if they are from a zone file
   # there's no caching of DNS lookups into the dictionary (by design, for now)
    cached_answer = False
    for target in reverse_records[revname] :
        if (debug) :
            print('check_reverse: cache MATCH %s %s' % (revname, target))
        cached_answer = True

    if (debug and not cached_answer) :
        print('check_reverse: cache NOMATCH %s' % (revname))
   # (optionally) see if we can find a real PTR record by DNS query
   # unless --no_dns is set
    if (no_dns) :
        return False
    if (force_query or not cached_answer) :
        answers = check_reverse_by_dns(revname)
        for rdata in answers:
            if (str(rdata) == str(fqdn)):
                if (debug) :
                    print('check_reverse: query MATCH %s %s' % (revname, rdata))
                return True # found at least one matching name
        if (debug):
            print('check_reverse: query NOMATCH %s' % (address))
        return False

    return cached_answer


def main():
    global debug, trace, no_dns, warning, doping, force_ptr_lookups
    trace = debug = warning = doping = force_ptr_lookups = False

    if len(sys.argv) < 2:
        print(usage)
        sys.exit()

    for arg in sys.argv[1:]:
        if (arg == '--debug') :
            debug = True
        elif (arg == '--trace') :
            trace = True
        elif (arg == '--no_dns') :
            no_dns = True
        elif (arg == '--warning') :
            warning = True
        elif (arg == '--ping') :
            doping = True
        elif (arg == '--force_ptr_lookups') :
            force_ptr_lookups = True
        else :
            zone_name.append(arg)

    if (trace) :
        print('debug %s, warning %s, no_dns %s, force_ptr_lookups %s, trace %s'
             % (debug, warning, no_dns, force_ptr_lookups, trace))
        print('zone_name(s) %s' % zone_name)



    if (force_ptr_lookups and no_dns):
        print('dueling DNS options')
        sys.exit()
     # go read all the zones via AXFR or zone file, depending on the argument
    for zone in zone_name :
       print('loading %s ...' % zone, end="")
       if (zone.endswith(zone_suffix)) :
           origin = strip_end(zone, zone_suffix)
           z = dns.zone.from_file(zone, origin, relativize = False)
           zone_type = 'forward'
       elif (zone.endswith(revzone_suffix)) :
           origin = strip_end(zone, revzone_suffix)
           z = dns.zone.from_file(zone, origin, relativize=False)
           zone_type = 'reverse'
       else:
           try:
               z = dns.zone.from_xfr(dns.query.xfr('ns1-int.scea.com', zone), relativize=False)
           except dns.exception.FormError :
               print('dns.exception.FormError: No answer or RRset not for qname')
               continue
          # some domains have the "wrong records" included
          # this can be a forward domain that has PTR records (which will never be referenced)
          # or reverse zones that contain PTR records
          # this is handleded in the zone loaders, based on the passed zone type
       forward_A_records_loaded = load_forward_records(z, 'A', zone_type)
       forward_AAAA_records_loaded = load_forward_records(z, 'AAAA', zone_type)
       reverse_Ptr_records_loaded = load_reverse_records(z, 'PTR', zone_type)
       print('%d A records, %d AAAA records, %d PTR records loaded (%d total)' %
             (forward_A_records_loaded, forward_AAAA_records_loaded, reverse_Ptr_records_loaded,
              (forward_A_records_loaded + forward_AAAA_records_loaded + reverse_Ptr_records_loaded)),
             end ="")
       print('done.')

    # walk all the forward records and do the following tests
    # 1. has a matching PTR
    # 2. is pingable (if requested)
    for fqdn in forward_records.keys():
       if (trace):
          print('forward <%s> address ' % fqdn, end="")
       addr_count = len(forward_records[fqdn])
       for addr in forward_records[fqdn] :
          # addr is an IPV4Address, is easier to check as a string

          if (check_reverse(fqdn, str(addr), force_ptr_lookups)) :
             # found at least one valid PTR that points to this name
             pass
  #            print('PTROK: host %s has A %s, found matching PTR' % (fqdn, addr))
          else:
             print('NOPTR: host %s has A %s, no matching PTR records found' % (fqdn, addr))

          if (doping):
              if (ping(str(addr))):
                  print('PING: host %s %s responds to ping' % (fqdn, addr))
              else:
                  print('NOPING: host %s %s no response to ping' % (fqdn, addr))

          if (debug):
             print('%s' % addr, end="")
             addr_count-= 1
             if (addr_count < 1):
                print()
             else:
                print(', ', end="")

    # walk all the reverse record and do the following tests
    # 1. we have at least one matching forward record
    for reverse in reverse_records.keys():
       if (debug):
          print('query <%s> target(s) ' % reverse, end="")
          reverse_count = len(reverse_records[reverse])
       for record in reverse_records[reverse] :
           try:
               check_reverse(record, dns.reversename.to_address(reverse), force_ptr_lookups)
           except dns.exception.SyntaxError :
               print('ERROR: Syntax error in PTR record <%s>' % reverse)
               continue
           if (debug):
               print('%s' % record, end="")
               reverse_count-= 1
               if (reverse_count < 1):
                   print()
               else:
                   print(', ', end="")



    sys.exit()

"""                             
   if (check_reverse(fqdn, str(addr))):
            # found at least one valid PTR that points to this name
            pass
#            print('PTROK: host %s has A %s, found matching PTR' % (fqdn, addr))
         else:
            print('NOPTR: host %s has A %s, no matching PTR records found' % (fqdn, addr))

         if (doping):
             if (ping(str(fqdn))):
                 pass
##            print('PING: host %s %s responds to ping' % (fqdn, addr))
             else:
                 print('NOPING: host %s %s no repsonse to ping' % (fqdn, addr))
"""

if __name__ == '__main__' :
   main()
