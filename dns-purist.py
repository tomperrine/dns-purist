#!/usr/local/bin/python3
import os, sys, collections
from pprint import pprint 
import ipaddress
import dns.query, dns.zone, dns.reversename, dns.resolver, dns.ipv4

#
# Global variables - TODO get rid of these
#
verbose = False
debug = False
# do or not allow "live" DNS lookups when trying to find matching PTRs for A/AAAA and v.v.
# command line flag
allow_dns_lookups = False
# silent mode
silent_no_output = False

#
# this is used when we're give a zone name instead of a file
# DNS server to AXFR from
## TODO - command line options, or try all advertised NS records
dns_server = 'ns1-int.scea.com'

# file suffixes used to tell forward and reverse zones based on filename
## TODO - use command line args like "--forward_zone" and "--reverse_zone"
# instead of magic file names
zone_suffix = '.zone'
revzone_suffix = '.revzone'
extzone_suffix = '.extzone'

#
# the three internal databases holding all records collected from all given zones
# no matter in which zone type they are found, all forwards, PTRs and CNAMES are inserted
# into these three databases
# this lets us find wrong record in wrong zone problems, such as PTR in forward zone and v.v

# a dict of lists of all the forward (A, AAAA) records
forward_records = collections.defaultdict(list)
# a dict of lists of all the CNAME records
cname_records = collections.defaultdict(list)
# a dict of lists of all the reverse (PTR) records
reverse_records = collections.defaultdict(list)
# a list of external domains, for which we just assume things are "valid"
external_zones = []


#
# helper functions
#
def debug_print(fmt, *args, **kwargs):
# print if debug option is set
# the only accepted keyword arg is "end"
    global debug
    try: m = fmt % args
    except:
        # Catch mismatch between fmt/args; prevents logging.info from
        # failing below, as well.
        m = fmt
        fmt = "%s"
    if (debug):
#        stderr.write("[%s] %s\n" % (time.asctime(), m))
        print(fmt, *args, **kwargs)



def silent_print(fmt, *args, **kwargs):
# the only accepted keyword arg is "end"
    try: m = fmt % args
    except:
        # Catch mismatch between fmt/args; prevents logging.info from
        # failing below, as well.
        m = fmt
        fmt = "%s"
    if (silent_no_output):
        return
    else:
#        stderr.write("[%s] %s\n" % (time.asctime(), m))
        print(fmt, *args, **kwargs)

def dns_error_print(fmt, *args, **kwargs):
# this is used to print all dicovered DNS errors
# the only accepted keyword arg is "end"
    try: m = fmt % args
    except:
        # Catch mismatch between fmt/args; prevents logging.info from
        # failing below, as well.
        m = fmt
        fmt = "%s"
    if (silent_no_output):
        return
    else:
#        stderr.write("[%s] %s\n" % (time.asctime(), m))
        print(fmt, *args, **kwargs)


def silent_endline():
    if (not silent_no_output):
        print()


def strip_end(text, suffix):
# strip the suffix from the string, if present
    if not text.endswith(suffix):
        return text
    return text[:len(text)-len(suffix)]

def is_valid_ip(addr):
    # is this a syntactically valid IP address string
    # (needed because the ipaddress package insists on throwing an error instead of giving a bool fcn)
    try:
        isitanaddr = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True

def in_external_zone(name):
# is this name (string) contained within any of the external zones
# if it is, return True, else False
    for extzone in external_zones:
        # we want to know if the given name is any kind of subset of the external zone
        debug_print('in_external_zone: name <%s> extzone <%s>' % (name,extzone))
        if (not (name.find(extzone) == -1)):
            # we found it, we're done
            return True
    return False


def does_it_resolve(name, record_type):
# give a hostname and record type, try to resolve it
# return True/False
    try:
        answers = dns.resolver.query(name, record_type)
    except dns.resolver.NXDOMAIN :
        return (False)
    except dns.exception.Timeout :
        dns_error_print('ERROR: %s: DNS Timeout' % name)
        return (False)
    except Exception as exception:
        dns_error_print('ERROR: %s: UNKNOWN resolver error' % name)
        dns_error_print(' exc: %s' % type(exception).__name__ )
    return (True)




def load_forward_records(zone, record_type, zone_type):
    global allow_dns_lookups
## for the given zone, load all records of the requested type (A or AAAA) into the global dictionary
## modifies global forward_records[] !!!
## as this will be called for ALL zones being loaded, we can also check for forward
## records that might be in a reverse zone
    record_count = 0
    # make sure we aren't trying to load non A or AAAA records into the forward dictionary
    # This would mean that we were called to load non forward records into the forward list
    if ( (record_type != 'A') and (record_type != 'AAAA')):
        silent_print('load_forward_records: invalid record type %s is not a forward record' % record_type)
        sys.exit()
   # search through the zone looking for A/AAAA
    for (fqdn, ttl, rdata) in zone.iterate_rdatas(record_type):
        # this is already a FQDN since we used relativize=False
        #special case to get rid of the self-reference record
        if (not fqdn):
            continue
        debug_print ('fqdn <%s> zone <%s>' % (fqdn, zone))
        # if the zone type isn't a forward zone, then we should not see any forward records, emit warning
        # remember that we search all zones (forward and reverse) for all record types, so even
        # though we're loading "forward records" we might be iterating through a reverse zone, looking
        # for these kinds of errors
        if (zone_type != 'forward'):
            silent_endline()
            dns_error_print('BADREC: forward record %s/%s found in reverse zone' % (fqdn,rdata.address))
            continue

        addr = ipaddress.ip_address(rdata.address)

        debug_print ('fqdn %s IP %s' % (fqdn, str(addr)))
        # append the address we just found to the list of addresses for this FQDN
        forward_records[fqdn].append(addr)
        record_count += 1
    return record_count


def load_reverse_records(zone, record_type, zone_type):
    global allow_dns_lookups
## for the given zone, load all records of the requested type (PTR) into the global dictionary
## modifies global reverse_records[] !!!
## as this will be called for ALL zones being loaded, we can also check for reverse
## records that might be in a forward zone
    record_count = 0
    #make sure we aren't trying to load non-PTR records into the reverse dictionary
    #which would be a parameter error
    if (record_type != 'PTR'):
      dns_error_print('load_reverse_records: invalid record type %s' % record_type)
      sys.exit()
    for (qname, ttl, rdata) in zone.iterate_rdatas(record_type):
        # this is already a full address since we used relativize=False
        debug_print ('load_reverse_records: qname %s target %s' % (qname, str(rdata.target)))
        # if the zone type isn't a reverse zone, then we shouldn't see any PTR records
        # remember that we search all zones (forward and reverse) for all record types, so even
        # though we're loading "forward records" we might be iterating through a reverse zone, looking
        # for these kinds of errors
        if (zone_type != 'reverse'):
            silent_endline()
            dns_error_print('BADREC: reverse record %s/%s found in forward zone' % (qname,rdata.target))
            continue
       # append the target we just found to the list of targets for this qname
        reverse_records[qname].append(rdata.target)
        record_count += 1
    return record_count

def load_cname_records(zone, zone_type):
# zone - zone to be loaded
# is it a forward or reverse zone?
## for the given zone, load all CNAME records into the global cname dictionary
## as this will be called for ALL zones being loaded, we can also check for CNAME
## records that might be in a reverse zone

## TODO - figure out how to deal with IP addresses as CNAME targets

    global allow_dns_lookups

    record_count = 0

    for (qname, ttl, rdata) in zone.iterate_rdatas('CNAME'):
        # the qname is already a FQDN since we used relativize=False
        debug_print ('load_cname_records: qname %s target %s' % (qname, str(rdata.target)))
        # if the zone type isn't a forward zone, then we shouldn't see any CNAME records
        # remember that we search all zones (forward and reverse) for all record types, so even
        # though we're loading "forward records" we might be iterating through a reverse zone, looking
        # for these kinds of errors
        if (zone_type != 'forward'):
            silent_endline()
            dns_error_print('BADREC: CNAME record %s/%s found in non-forward zone' % (qname,rdata.target))
            continue
        # append the target we just found to the list of targets for this qname
        cname_records[qname].append(rdata.target)
        record_count += 1
    return record_count

def load_external_zones(file):
    global allow_dns_lookups
## for the given file, load each zone name into the list
## returns the number of zone names loaded
## modifies global external)zones
    external_zone_count = 0

    with open(file, 'r') as fp :
        for line in fp :
            external_zone_count += 1
            external_zones.append(line.strip())

    silent_print(external_zones)
    silent_print ('loading external zones from %s: %d zones' % (file, external_zone_count))
    return external_zone_count


def find_any_forward_by_dns(hostname):
# given a hostname, see if it can be resolved as an A, AAAA, or CNAME record
# return True on the first(any) match, return False if not resolvable at all
    for rec_type in ("A", "AAAA", "CNAME"):
        if (does_it_resolve(hostname, rec_type)):
            # found a valid record, done
            return True
    # eventually found nothing, return False
    return False


def find_reverse_from_forward_by_dns(revname):
# given a reversed form of an IP address, with the proper suffix (e.g. in-addr.arpa, ip6.arpa)
# use DNS lookup to see of there are one or more PTR records for it
# returns a list of all matching PTR records
    global allow_dns_lookups

    debug_print('find_reverse_from_forward_by_dns %s' % revname)
    try:
        answers = dns.resolver.query(revname, 'PTR')
    except dns.resolver.NXDOMAIN :
        #      dns_error_print('ERROR: %s: no PTR' % address)
        return ""
    except dns.exception.Timeout :
        dns_error_print('ERROR: %s: DNS Timeout' % revname)
        return ""
    except Exception as exception:
        dns_error_print('ERROR: %s: UNKNOWN resolver error' % revname)
        dns_error_print(' exc: %s' % type(exception).__name__ )
        return ""
    return answers


def find_reverse_from_forward(fqdn, address, allow_dns_query):
# given an FQDN and IP address:
# 1. ensure that the address is valid IP address
# 2. ensure that the address has a PTR record that matches the FQDN (check the DB, optionally do a DNS call based on allow_dns_query)
# ignore any extra PTR records that may match other FQDNs. they will be checked during some other call on some other FQDN
# returns True if a MATCH is found, False otherwise even if there are SOME PTRs for the address
    global allow_dns_lookups

    debug_print('find_reverse_from_forward: fqdn %s address <%s> allow_dns_query %s' % (fqdn, address, allow_dns_query))

   # is this a valid IP address?
    if ( (not fqdn) or (not address)):
        silent_print('find_reverse_from_forward: bad arguments %s %s' % (fqdn, address))
        sys.exit()
    if (not is_valid_ip(address)):
        silent_print('ERROR: %s :invalid IP address' % address)
        return False

   # get the reverse form of the IP address
    revname = dns.reversename.from_address(address)
    debug_print('find_reverse_from_forward: address <%s>, revname <%s>' % (address, revname))

   # first, see if we have any PTR records at all
   # then, see if any of them match the given FQDN
   # records are only loaded/cached if they are from a zone file
   # there's no caching of DNS lookups into the dictionary (by design, for now)

# let's try the cache first
    for target in reverse_records[revname] :
        debug_print('checking cache - target <%s>, fqdn <%s>' % (target, fqdn))
        if (target == fqdn) :
            debug_print('find_reverse_from_forward: cache MATCH %s %s %s' % (revname, target, fqdn))
            return True

    # at this point we haven't found any matching PTR records in the local db
    # lets see if we should try DNS and what we get

    debug_print('find_reverse_from_forward: cache NOMATCH %s' % (revname))
    # (optionally) see if we can find a real PTR record by DNS query
    if (not allow_dns_lookups) :
        return False
    else:
        answers = find_reverse_from_forward_by_dns(revname)
        for rdata in answers:
            if (str(rdata) == str(fqdn)):
                debug_print('find_reverse_from_forward: query MATCH %s %s' % (revname, rdata))
                return True # found at least one matching name
        debug_print('find_reverse_from_forward: query NOMATCH %s' % (address))
        return False
    return False

############
def find_forward_from_reverse(fqdn, address):
# given an FQDN and IP address:
# 0. if the address (reversed) appears in the skip list, consider it found and return TRUE
# 1. ensure that the address has a forward address record that matches the FQDN (check the DB, no DNS calls)
# ignore any extra PTR records that may match other FQDNs. they will be checked during some other call on some other FQDN
# returns True if a MATCH is found, False otherwise even if there are SOME PTRs for the address
# 2. if there is a forward, and it appears in the skip list, consider it found immediately

    temp_ptr = ipaddress.ip_address(address).reverse_pointer

    debug_print('find_forward_from_reverse: fqdn %s address <%s> reverse <%s>' % (fqdn, address, temp_ptr))

    if (in_external_zone(temp_ptr)):
        return True


   # first, see if we have any forwards for the FQDN records at all
   # then, see if any of them match the given address

    # we're only looking in the DB, not in DNS
    for target in forward_records[fqdn] :
        debug_print('find_forward_from_reverse - target <%s>, address <%s>' % (target, address))
        if (str(target) == str(address)) :
            debug_print('find_forward_from_reverse: cache MATCH target %s address %s' % (target, address))
            return True
    return False

###########

def check_all_forwards() :
# walk all the forward records and do the following tests
# 1. has at least one matching PTR
# 2. is in one of our known netblocks ##TODO
    missing_ptr_count = 0
    for fqdn in forward_records.keys():
        debug_print('forward <%s> address ' % fqdn, end="")
        addr_count = len(forward_records[fqdn])
        for addr in forward_records[fqdn] :
          # addr is an IPV4Address, is easier to check as a string
            if (find_reverse_from_forward(fqdn, str(addr), allow_dns_lookups)) :
                # found at least one valid PTR that points to this name
                pass
            else:
                dns_error_print('NO_PTR: host %s has A %s, no matching PTR records found' % (fqdn, addr))
                missing_ptr_count += 1

             ## FIXME - should use debug_print but there's logic here that needs to be cleaned
            if (debug):
                debug_print('%s' % addr, end="")
                addr_count-= 1
                if (addr_count < 1):
                    silent_endline()
                else:
                    dns_error_print(', ', end="")

    debug_print('check_all_forwards returning %d' % missing_ptr_count)
    return missing_ptr_count

def check_all_reverses() :
# walk all the reverse record and do the following tests
# 1. we have at least one matching forward record
    missing_forward_count = 0
    for reverse in reverse_records.keys():
        debug_print('check_all_reverses (main loop): query <%s> target ' % reverse)
        for record in reverse_records[reverse] :
            try:
                # python3.6.x - change from 3.5.0 requires .decode here
                # python3.7.7 - have to take out all the .decode()
                if (find_forward_from_reverse(record, dns.reversename.to_address(reverse))) :
                    debug_print('FORWARD_OK: addr %s has forward %s' % (reverse, record))
                else:
                    dns_error_print('NO_FORWARD: addr %s has no matching forward' % (reverse))
                    missing_forward_count += 1
            except dns.exception.SyntaxError :
                dns_error_print('ERROR: Syntax error in PTR record <%s>' % reverse)
                continue
    debug_print('check_all_reverses returning %d' % missing_forward_count)
    return missing_forward_count


def check_all_cnames() :
# walk all the cname records and do the following tests
# 1. there is not more than one CNAME records for the same name
# 2. the target of the CNAME is NOT an IP address
###  TODO - this test is BROKEN, sort of, see below
# 3. the target of the cname resolvable, either in the forward_records dictionary
#    or optionally resolved via DNS
# 4. if the name is within the external domain skip list, then just quit early
    cname_errors = 0
    for cname in cname_records.keys():
        debug_print('cname <%s> target(s) ' % cname, end="")
        addr_count = len(cname_records[cname])
        # test for multiple CNAMEs
        if (addr_count > 1):
            dns_error_print('CNAME_ERR: multiple CNAMES for %s' % cname)
            cname_errors += 1
        # walk all the CNAMEs for this name, checking them all
        for rdata in cname_records[cname] :
            # is the target a valid IP address?
            # TODO - this is broken - the zones were loaded with relativize=False
            # TODO -    so this test will never work - need to strip the zone (if present)
            # TODO -    somewhere around here in order to see if the portion is an IP address
            if (is_valid_ip(rdata)):
                dns_error_print('CNAME_ERR_ADDRESS: CNAME %s -> %s' % (cname, rdata))
                cname_errors += 1
                # no need to check to see if resolvable
                continue
            # is the rdata pointing to a domain in the external skip list?
            if (in_external_zone(str(rdata))):
                # if so, just pretend it doesn't exist, go on
                continue
            # is the target "resolvable"
            # was it in a loaded zone?
            if (forward_records[rdata]):
                # it's in the cache, we're done and OK
                debug_print('CNAME_OK: CNAME  %s ->  %s -> %s' % (cname, rdata, forward_records[cname]))
                continue
            else :
                ## should we try to resolve this via DNS query?
                if (allow_dns_lookups):
                    if (not (find_any_forward_by_dns(rdata))):
                        dns_error_print('CNAME_ERR_NOT_RESOLVED: CNAME  %s ->  %s which does not resolve' % (cname.to_text(omit_final_dot=True), rdata))
                        cname_errors += 1
                    # continue either way
                    continue
                else :
                    # nope, not going to try DNS, so just error and continue
                    cname_errors += 1
                    dns_error_print('CNAME_ERR_NOT_FOUND: CNAME  %s ->  %s which is not in a loaded zone' % (cname.to_text(omit_final_dot=True), rdata))
    return cname_errors

def dump_all_forward_addresses():
# print all the forward record ADDRESSES to STDOUT
# to provide a target list file for input into nmap
# want to use IPs for the target list, instead of names to avoid
# DNS queries in nmap
    for fqdn in forward_records.keys():
        for addr in forward_records[fqdn] :
            silent_print('%s' % (addr))

def dump_all_reverse_addresses():
# print all the PTR record ADDRESSES to STDOUT
    for reverse in reverse_records.keys():
        silent_print('%s' % dns.reversename.to_address(reverse))

def dump_all_forward_names():
# print all the forward record NAMES to STDOUT
    for fqdn in forward_records.keys():
        silent_print('%s' % fqdn)

def dump_all_records(single_line):
# two cases
# original/default: for each record print both the name and the IP address
# single_line mode: print the name followed by a comma-separated list of IP addresses

# easiest and cleanist to do very separately
# do the original version first
    if (not single_line):
        for fqdn in forward_records.keys():
            for addr in forward_records[fqdn] :
                silent_print('%s %s' % (fqdn,addr))
    else :
        for fqdn in forward_records.keys():
            silent_print('%s' % fqdn, end='')
            for addr in forward_records[fqdn] :
                silent_print(',%s' % addr, end='')
            silent_print('')
# and the reverses - inherently only a single line
    for reverse in reverse_records.keys():
        silent_print('%s %s' % (reverse, dns.reversename.to_address(reverse)))

def main():
    global verbose, debug, allow_dns_lookups, silent_no_output
    # list of zones to process
    zone_names = []


    usage = 'Usage: dns-purist [--debug] [--verbose][--csv_output | --dump_ips | --dump_names | --dump_records [--single_line]] [--allow_dns_lookups] targetzone, zonefile.zone, zonefile.revzone zonefile.extzone'
    make_list_for_nmap = False
    verbose = debug = allow_dns_lookups = dump_ips = dump_names = dump_records = single_line = False
    silent_no_output = dump_csvs = False

    missing_ptrs = missing_forwards = cname_errors = 0

    if len(sys.argv) < 2:
        silent_print(usage)
        sys.exit()

    for arg in sys.argv[1:]:
        if (arg == '--verbose') :
            verbose = True
        elif (arg == '--debug') :
            debug = True
        elif (arg == '--allow_dns_lookups') :
            allow_dns_lookups = True
        elif (arg == '--dump_ips') :
            dump_ips = True
        elif (arg == '--dump_names') :
            dump_names = True
        elif (arg == '--dump_records') :
            dump_records = True
        elif (arg == '--single_line') :
            single_line = True
        elif (arg == '--csv_output') :
            dump_csvs = True
        else :
            zone_names.append(arg)

    # go read all the zones via AXFR or zone file, depending on the argument
    # and process each zone multiple times, once for A records, once for AAAA, once for CNAME and once for PTR
    total_zones = 0
    total_a_records = 0
    total_aaaa_records = 0
    total_reverse_records = 0
    total_cname_records = 0
    total_external_zones = 0

    for zone in zone_names :
        if (verbose):
            print('loading %s ... ' % zone, end="")
        total_zones += 1
        if (zone.endswith(zone_suffix)) :
            origin = strip_end(zone, zone_suffix)
            origin = os.path.basename(origin)
            z = dns.zone.from_file(zone, origin, relativize = False)
            zone_type = 'forward'
        elif (zone.endswith(revzone_suffix)) :
            origin = strip_end(zone, revzone_suffix)
            origin = os.path.basename(origin)
            z = dns.zone.from_file(zone, origin, relativize=False)
            zone_type = 'reverse'
        elif (zone.endswith(extzone_suffix)) :
            total_external_zones += load_external_zones(zone)
            # we can bail to the next arg, we've already done all the processing needed
            # for this arg at this point
            continue
        else:
           try:
               z = dns.zone.from_xfr(dns.query.xfr(dns_server, zone), relativize=False)
           except dns.exception.FormError :
               silent_print('dns.exception.FormError: No answer or RRset not for qname')
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

        total_a_records += forward_A_records_loaded
        total_aaaa_records += forward_AAAA_records_loaded

       ## TODO - the zones were all loaded with relativize=False, so had the zone name appended if not present
        cnames_loaded = load_cname_records(z, zone_type)
        total_cname_records += cnames_loaded

        reverse_ptr_records_loaded = load_reverse_records(z, 'PTR', zone_type)
        total_reverse_records += reverse_ptr_records_loaded

        if (verbose):
            print('%d A records, %d AAAA records, %d CNAME records, %d PTR records loaded (%d total) ' %
             (forward_A_records_loaded, forward_AAAA_records_loaded, cnames_loaded, reverse_ptr_records_loaded,
              (forward_A_records_loaded + forward_AAAA_records_loaded + cnames_loaded + reverse_ptr_records_loaded)))


    # now that we have all the data loaded...

    if (dump_ips) :
        dump_all_forward_addresses()
        dump_all_reverse_addresses()
    elif (dump_names) :
        dump_all_forward_names()
        sys.exit()
    elif (dump_records):
        dump_all_records(single_line)
    else :
        # do all the forward record tests
        missing_ptrs = check_all_forwards()
        # do all the reverse record tests
        missing_forwards = check_all_reverses()
        # and cnames
        cname_errors = check_all_cnames()

        if (dump_csvs):
            print('zones loaded,A records,AAAA records,CNAME records, PTR records, missing PTR records, missing A/AAAA records, CNAME errors')
            print('%d,%d,%d,%d,%d,%d,%d,%d' %
                  (total_zones, total_a_records, total_aaaa_records, total_cname_records, total_reverse_records, missing_ptrs, missing_forwards, cname_errors))
        else:
            silent_print('GRAND TOTALS: %d zones loaded. %d A records, %d AAAA records, %d CNAME records, %d PTR records loaded (%d total) ' %
                         (total_zones, total_a_records, total_aaaa_records, total_cname_records, total_reverse_records,
                          (total_a_records + total_aaaa_records + total_cname_records + total_reverse_records)))
            silent_print('ERRORS: %d missing PTR records, %d missing A/AAAA records, %d CNAME errors ' % (missing_ptrs, missing_forwards, cname_errors))


    sys.exit()


if __name__ == '__main__' :
   main()
