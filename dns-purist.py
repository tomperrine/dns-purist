#!/usr/local/bin/python3

import sys, collections
import pprint
import ipaddress
import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

debug = True
trace = False
no_dns= False
arg_allow_dns_lookups = False

# DNS server to AXFR from
dns_server = 'ns1-int.scea.com'
zone_suffix = '.zone'
revzone_suffix = '.revzone'


zone_name = []

# a dict of lists of all the forward (A, AAAA) records
forward_records = collections.defaultdict(list)
# a dict of lists of all the reverse (PTR) records
reverse_records = collections.defaultdict(list)


usage = 'Usage: dns-purist [--trace] [--debug] [--warning] [--ping] [--no_dns] [--arg_allow_dns_lookups] targetzone, zonefile.zone, zonefile.revzone'

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
        ping_str = "-c 1 -o -n "  #MacOS, 1 packet, only wait for one packet, no DNS lookup
        redirect = ' >/dev/null'

    # Ping
    return (os.system("ping " + ping_str + " " + address + " " + redirect) == 0)


def strip_end(text, suffix):
# strip the suffix from the string, if present
    if not text.endswith(suffix):
        return text
    return text[:len(text)-len(suffix)]



def ping_all_reverses() :
## ping all the addresses from the reverse zones that have been loaded
    for reverse in reverse_records.keys():
        # these are in .in-addr.arpa and   format
        addr = dns.reversename.to_address(reverse)
        if (debug):
            print('ping <%s> target' % addr)
        if (ping(str(addr))):
            print('PING: host %s responds to ping' % (addr))
        else:
            print('NOPING: host %s no response to ping' % (addr))


def ping_all_the_things():
## try at least a ping to everything, keeping track of things that didn't answer
## so we don't try any device more than once

    # do the reverses first, since no DNS lookups needed
    # this will also load the cache of things that didn't answer
    ping_all_reverses()

    # now the forwards
    # should I have kept the results of the DNS lookups for the forward records
    # from the check_all_forwards() ?
##    ping_all_forwards()


def load_forward_records(zone, record_type, zone_type):
    global debug, trace, no_dns, warning, doping, arg_allow_dns_lookups
## for the given zone, load all records of the requested type (A or AAAA) into the global dictionary
## modifies global forward_records[] !!!
## as this will be called for ALL zones being loaded, we can also check for forward
## records that might be in a reverse zone
    record_count = 0
    # make sure we aren't trying to load non A or AAAA records into the forward dictionary
    # (parameter error)
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
      # if the zone type isn't a forward zone, then we should not see any forward records, emit warning
        if (zone_type != 'forward'):
            print()
            print('BADREC: forward record %s/%s found in reverse zone' % (fqdn,rdata.address))
            continue

        addr = ipaddress.ip_address(rdata.address)

        if (debug):
            print ('fqdn %s IP %s' % (fqdn, str(addr)))
        # append the address we just found to the list of addresses for this FQDN
        forward_records[fqdn].append(addr)
        record_count += 1
    return record_count


def load_reverse_records(zone, record_type, zone_type):
    global debug, trace, no_dns, warning, doping, arg_allow_dns_lookups
## for the given zone, load all records of the requested type (PTR) into the global dictionary
## modifies global reverse_records[] !!!
## as this will be called for ALL zones being loaded, we can also check for reverse
## records that might be in a forward zone
    record_count = 0
    #make sure we aren't trying to load non-PTR records into the reverse dictionary
    #which would be a parameter error
    if (record_type != 'PTR'):
      print('load_reverse_records: invalid record type %s' % record_type)
      sys.exit()
    for (qname, ttl, rdata) in zone.iterate_rdatas(record_type):
        # this is already a full address since we used relativize=False
        if (debug):
            print ('load_reverse_records: qname %s target %s' % (qname, str(rdata.target)))
        # if the zone type isn't a reverse zone, then we shouldn't see any PTR records
        if (zone_type != 'reverse'):
            print()
            print('BADREC: reverse record %s/%s found in forward zone' % (qname,rdata.target))
            continue
       # append the target we just found to the list of targets for this qname
        reverse_records[qname].append(rdata.target)
        record_count += 1
    return record_count

def find_reverse_from_forward_by_dns(revname):
# returns all answers
    global debug, trace, no_dns, warning, doping, arg_allow_dns_lookups

    if (trace):
        print('find_reverse_from_forward_by_dns %s' % revname)
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


def find_reverse_from_forward(fqdn, address, allow_dns_query):
# given an FQDN and IP address:
# 1. ensure that the address is valid IP address
# 2. ensure that the address has a PTR record that matches the FQDN (check the DB, optionally do a DNS call based on allow_dns_query)
# ignore any extra PTR records that may match other FQDNs. they will be checked during some other call on some other FQDN
# returns True if a MATCH is found, False otherwise even if there are SOME PTRs for the address
    global debug, trace, no_dns, warning, doping, arg_allow_dns_lookups

    if (trace):
        print('find_reverse_from_forward: %s %s %s' % (fqdn, address, allow_dns_query))

   # is this a valid IP address?
    if ( (not fqdn) or (not address)):
        print('find_reverse_from_forward: bad arguments %s %s' % (fqdn, address))
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

   # first, see if we have any PTR records at all
   # then, see if any of them match the given FQDN
   # records are only loaded/cached if they are from a zone file
   # there's no caching of DNS lookups into the dictionary (by design, for now)

# lets' try the cache first
    for target in reverse_records[revname] :
        if (target == fqdn) :
            if (debug) :
                print('find_reverse_from_forward: cache MATCH %s %s %s' % (revname, target, fqdn))
                return True

    # at this point we haven't found any matching PTR records in the local db
    # lets see if we should try DNS and what we get

    if (debug) :
        print('find_reverse_from_forward: cache NOMATCH %s' % (revname))
   # (optionally) see if we can find a real PTR record by DNS query
   # unless --no_dns is set
    if (no_dns) :
        return False

    if (allow_dns_query) :
        answers = find_reverse_from_forward_by_dns(revname)
        for rdata in answers:
            if (str(rdata) == str(fqdn)):
                if (debug) :
                    print('find_reverse_from_forward: query MATCH %s %s' % (revname, rdata))
                return True # found at least one matching name
            else :
                if (debug) :
                    print('find_reverse_from_forward: unmatched PTR %s %s' % (revname, rdata))
                return False # found at least one PTR record, but it didn't match
        if (debug):
            print('find_reverse_from_forward: query NOMATCH %s' % (address))
        return False
    return False

def check_all_forwards() :
# walk all the forward records and do the following tests
# 1. has at least one matching PTR
# 2. is in one of our known netblocks ##TODO
    for fqdn in forward_records.keys():
       if (trace):
          print('forward <%s> address ' % fqdn, end="")
       addr_count = len(forward_records[fqdn])
       for addr in forward_records[fqdn] :
          # addr is an IPV4Address, is easier to check as a string
          if (find_reverse_from_forward(fqdn, str(addr), arg_allow_dns_lookups)) :
             # found at least one valid PTR that points to this name
             pass
  #            print('PTROK: host %s has A %s, found matching PTR' % (fqdn, addr))
          else:
             print('NOPTR: host %s has A %s, no matching PTR records found' % (fqdn, addr))

          if (debug):
             print('%s' % addr, end="")
             addr_count-= 1
             if (addr_count < 1):
                print()
             else:
                print(', ', end="")

def check_all_reverses() :
# walk all the reverse record and do the following tests
# 1. we have at least one matching forward record

    for reverse in reverse_records.keys():
        if (debug):
            print('query <%s> target(s) ' % reverse, end="")
        for record in reverse_records[reverse] :
            try:
                if (find_reverse_from_forward(record, dns.reversename.to_address(reverse), arg_allow_dns_lookups)) :
                    if (debug) :
                        print('FORWARD_OK: addr %s has forward %s' % (reverse, record))
                else:
                    print('NO_FORWARD: addr %s has NO matching forward' % (reverse))
            except dns.exception.SyntaxError :
                print('ERROR: Syntax error in PTR record <%s>' % reverse)
                continue


def main():
    global debug, trace, no_dns, warning, doping, arg_allow_dns_lookups
    trace = debug = warning = doping = arg_allow_dns_lookups = False

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
        elif (arg == '--allow_dns_lookups') :
            arg_allow_dns_lookups = True
        else :
            zone_name.append(arg)

    if (trace) :
        print('debug %s, warning %s, no_dns %s, arg_allow_dns_lookups %s, trace %s'
             % (debug, warning, no_dns, arg_allow_dns_lookups, trace))
        print('zone_name(s) %s' % zone_name)



    if (arg_allow_dns_lookups and no_dns):
        print('dueling DNS options')
        sys.exit()

    # go read all the zones via AXFR or zone file, depending on the argument
    # and process each zone 3 times, once for A records, once for AAAA and once for PTR
    for zone in zone_name :
       print('loading %s ... ' % zone)
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
               z = dns.zone.from_xfr(dns.query.xfr(dns_server, zone), relativize=False)
           except dns.exception.FormError :
               print('dns.exception.FormError: No answer or RRset not for qname')
               continue
## FIXME - can determine whether forward or not by checking the zone name after we fetch it
           if zone.endswith("ip6.arpa") or zone.endswith("in-addr.arpa") :
               zone_type = 'reverse'
           else :
               zone_type = 'forward'

        # in order to properly process all types of records, we have to
        # make multiple passes over each zone, one pass for each record type
       forward_A_records_loaded = load_forward_records(z, 'A', zone_type)
       forward_AAAA_records_loaded = load_forward_records(z, 'AAAA', zone_type)
       reverse_Ptr_records_loaded = load_reverse_records(z, 'PTR', zone_type)
       print('%d A records, %d AAAA records, %d PTR records loaded (%d total)' %
             (forward_A_records_loaded, forward_AAAA_records_loaded, reverse_Ptr_records_loaded,
              (forward_A_records_loaded + forward_AAAA_records_loaded + reverse_Ptr_records_loaded)),
             end ="")
       print('done.')

    # now that we have all the data loaded...
    # do all the forward record tests
##    check_all_forwards()
    # do all the reverse record tests
##    check_all_reverses()
    ###TODO 
    # check ping if requested
    ping_all_the_things()

    sys.exit()

"""                             
   if (find_reverse_from_forward(fqdn, str(addr))):
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
